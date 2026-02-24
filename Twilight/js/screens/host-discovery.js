/*
 * Copyright (C) 2025 Twilight Contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
'use strict';

/**
 * Host Discovery Screen
 *
 * Displays saved hosts, checks their online status via the
 * GameStream/Sunshine HTTP API, and handles the "Add Host" flow.
 *
 * GameStream server info endpoint: http://<host>:47989/serverinfo
 * Response is XML; status_code=200 means reachable.
 */
var HostDiscovery = (function () {

    var GS_HTTP_PORT     = 47989;
    var CHECK_TIMEOUT    = 5000;   // ms
    var _pendingRemoveId = null;   // host ID awaiting removal confirmation
    var _pendingUnpairId = null;   // host ID awaiting unpair confirmation

    /* ── Utilities ── */

    function esc(str) {
        var d = document.createElement('div');
        d.appendChild(document.createTextNode(String(str)));
        return d.innerHTML;
    }

    function fetchWithTimeout(url, ms) {
        return new Promise(function (resolve, reject) {
            var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
            var timer = setTimeout(function () {
                if (controller) controller.abort();
                reject(new Error('timeout'));
            }, ms);

            var opts = controller ? { signal: controller.signal } : {};
            fetch(url, opts).then(function (r) {
                clearTimeout(timer);
                resolve(r);
            }).catch(function (e) {
                clearTimeout(timer);
                reject(e);
            });
        });
    }

    /* ── Host Card DOM ── */

    function statusLabel(status) {
        return { online: 'Online', offline: 'Offline', pairing: 'Needs Pairing', unknown: 'Checking...' }[status] || 'Unknown';
    }

    function renderHostCard(host) {
        var card = document.createElement('div');
        card.className = 'host-card focusable';
        card.tabIndex  = 0;
        card.dataset.navId  = 'host-' + host.id;
        card.dataset.hostId = host.id;
        card.dataset.action = 'select-host';

        var st = host.status || 'unknown';
        card.innerHTML =
            '<div class="host-card-header">' +
                '<div class="host-status-dot ' + st + '"></div>' +
                '<span class="host-name">' + esc(host.name) + '</span>' +
            '</div>' +
            '<span class="host-ip">' + esc(host.ip) + '</span>' +
            '<span class="host-status-label ' + st + '">' + statusLabel(st) + '</span>' +
            (!host.paired ? '<span class="badge badge-pairing" style="align-self:flex-start;margin-top:auto">Not Paired</span>' : '');

        return card;
    }

    /* ── Render ── */

    function render() {
        var grid  = document.getElementById('host-grid');
        var empty = document.getElementById('host-empty');
        var hosts = Storage.getHosts();

        // Remove old host cards; keep the Scan action card
        Array.prototype.forEach.call(
            grid.querySelectorAll('.host-card:not(.host-card-scan)'),
            function (c) { c.remove(); }
        );

        var scanCard = grid.querySelector('.host-card-scan');
        hosts.forEach(function (host) {
            grid.insertBefore(renderHostCard(host), scanCard);
        });

        if (empty) empty.classList.toggle('hidden', hosts.length > 0);
    }

    /* ── Status Check ── */

    function checkHost(host) {
        /* NOTE: Sunshine's HTTP /serverinfo endpoint ALWAYS returns
         * PairStatus=0 regardless of actual pairing state.  Only the
         * HTTPS endpoint returns PairStatus=1 (for any request that
         * carries a uniqueid parameter).  We therefore do NOT update
         * host.paired from this check – the paired flag is the sole
         * responsibility of the pairing flow (pairing.js onSuccess).
         *
         * We still send uniqueid so Sunshine can log / rate-limit
         * per-client, but we ignore the PairStatus in the response.  */
        var uid = (typeof TwilightIdentity !== 'undefined' && TwilightIdentity.isReady())
            ? TwilightIdentity.getUniqueId()
            : null;
        var url = 'http://' + host.ip + ':' + GS_HTTP_PORT + '/serverinfo' +
            (uid ? '?uniqueid=' + encodeURIComponent(uid) : '');

        fetchWithTimeout(url, CHECK_TIMEOUT)
            .then(function (r) { return r.text(); })
            .then(function (xml) {
                var parser = new DOMParser();
                var doc    = parser.parseFromString(xml, 'text/xml');
                var code   = (doc.querySelector('root') || {}).getAttribute
                    ? doc.querySelector('root').getAttribute('status_code')
                    : null;

                if (code === '200') {
                    var hostnameEl = doc.querySelector('hostname');
                    host.status = 'online';
                    /* Do NOT read or write host.paired here – see note above. */
                    if (hostnameEl && hostnameEl.textContent) host.name = hostnameEl.textContent;
                } else {
                    host.status = 'offline';
                }
                Storage.saveHost(host);
                updateCard(host);
            })
            .catch(function () {
                host.status = 'offline';
                Storage.saveHost(host);
                updateCard(host);
            });
    }

    function updateCard(host) {
        var card = document.querySelector('[data-host-id="' + host.id + '"]');
        if (!card) return;
        var dot   = card.querySelector('.host-status-dot');
        var lbl   = card.querySelector('.host-status-label');
        var badge = card.querySelector('.badge-pairing');
        var st    = host.status || 'unknown';
        if (dot) dot.className = 'host-status-dot ' + st;
        if (lbl) { lbl.textContent = statusLabel(st); lbl.className = 'host-status-label ' + st; }
        /* Sync the "Not Paired" badge with the current paired state */
        if (host.paired && badge) {
            badge.parentNode.removeChild(badge);
        } else if (!host.paired && !badge) {
            var newBadge = document.createElement('span');
            newBadge.className = 'badge badge-pairing';
            newBadge.style.cssText = 'align-self:flex-start;margin-top:auto';
            newBadge.textContent = 'Not Paired';
            card.appendChild(newBadge);
        }
    }

    /* ── Host Selection ── */

    function onSelect(hostId) {
        var host = Storage.getHost(hostId);
        if (!host) return;

        if (host.status === 'offline') {
            App.showToast('Host is offline', 'error');
            return;
        }
        if (!host.paired) {
            App.navigate('pairing', { host: host });
            return;
        }
        App.navigate('apps', { host: host });
    }

    /* ── Remove Host ── */

    function openRemoveHostModal(hostId) {
        var host = Storage.getHost(hostId);
        if (!host) return;
        _pendingRemoveId = hostId;
        var msgEl = document.getElementById('remove-host-confirm-msg');
        if (msgEl) {
            msgEl.textContent =
                'Remove \u201c' + host.name + '\u201d from Twilight? ' +
                'This does not unpair the device from Sunshine.';
        }
        App.openModal('remove-host');
    }

    function removeHost(hostId) {
        if (!hostId) return;
        var host = Storage.getHost(hostId);
        var name = host ? host.name : 'Host';
        Storage.removeHost(hostId);
        _pendingRemoveId = null;
        App.closeModal();
        render();
        Navigation.focusDefault();
        App.showToast('\u201c' + name + '\u201d removed', 'info');
    }

    /* ── Unpair Host ── */

    function openUnpairModal(hostId) {
        var host = Storage.getHost(hostId);
        if (!host || !host.paired) return;
        _pendingUnpairId = hostId;
        var msgEl = document.getElementById('host-unpair-confirm-msg');
        if (msgEl) {
            msgEl.textContent =
                'Remove Twilight from \u201c' + host.name +
                '\u2019s paired clients? You will need to re-pair to stream games.';
        }
        App.openModal('host-unpair');
    }

    function doUnpair(hostId) {
        if (!hostId) return;
        var host = Storage.getHost(hostId);
        if (!host) return;
        var name = host.name;

        /* Fire-and-forget HTTP /unpair – local state update is authoritative */
        var uid = (typeof TwilightIdentity !== 'undefined' && TwilightIdentity.isReady())
            ? TwilightIdentity.getUniqueId()
            : null;
        if (uid) {
            fetch('http://' + host.ip + ':' + GS_HTTP_PORT +
                  '/unpair?uniqueid=' + encodeURIComponent(uid) +
                  '&devicename=roth'
            ).catch(function () {});
        }

        host.paired = false;
        Storage.saveHost(host);
        _pendingUnpairId = null;
        App.closeModal();
        render();
        Navigation.focusDefault();
        App.showToast('Unpaired from \u201c' + name + '\u201d', 'info');
    }

    /* ── Network Scan ── */

    var _scanning = false;  // guard against concurrent scan requests

    /**
     * Trigger a Sunshine/GameStream host discovery scan via the Twilight
     * background service (com.twilightstream.client.service).
     * Discovered hosts not already in storage are added automatically.
     */
    function scanNetwork() {
        if (typeof webOS === 'undefined') {
            App.showToast('Network scan requires webOS', 'warning');
            return;
        }
        if (_scanning) {
            App.showToast('Scan already in progress\u2026', 'info');
            return;
        }

        var scanCard  = document.querySelector('[data-action="scan-network"]');
        var scanLabel = scanCard && scanCard.querySelector('.scan-label');

        _scanning = true;
        if (scanCard) scanCard.classList.add('scanning');
        if (scanLabel) scanLabel.textContent = 'Scanning\u2026';
        App.showToast('Scanning for Sunshine hosts\u2026', 'info');

        webOS.service.request('luna://com.twilightstream.client.service', {
            method:     'scan',
            parameters: { timeout: 5000 },
            onSuccess: function (result) {
                _scanning = false;
                if (scanCard)  scanCard.classList.remove('scanning');
                if (scanLabel) scanLabel.textContent = 'Scan Network';

                var found   = 0;
                var already = 0;

                // Build a set of already-known IPs (fetch once, not inside loop)
                var knownIps = {};
                Storage.getHosts().forEach(function (h) { knownIps[h.ip] = true; });

                (result.hosts || []).forEach(function (discovered) {
                    if (knownIps[discovered.ip]) {
                        already++;
                        return;
                    }
                    // Track within this scan result to catch service-side duplicates
                    knownIps[discovered.ip] = true;
                    var host = Storage.createHost(discovered.ip, discovered.name || '');
                    Storage.saveHost(host);
                    found++;
                });

                if (found > 0) {
                    render();
                    Storage.getHosts().forEach(checkHost);
                    App.showToast(
                        'Found ' + found + ' new host' + (found !== 1 ? 's' : ''),
                        'success'
                    );
                } else if (already > 0) {
                    App.showToast(
                        'No new hosts found (' + already + ' already saved)',
                        'info'
                    );
                } else {
                    App.showToast('No Sunshine hosts found on this network', 'warning');
                }
            },
            onFailure: function (err) {
                _scanning = false;
                if (scanCard)  scanCard.classList.remove('scanning');
                if (scanLabel) scanLabel.textContent = 'Scan Network';
                App.showToast(
                    'Scan failed: ' + ((err && err.errorText) || 'Service unavailable'),
                    'error'
                );
            },
        });
    }

    /* ── Public ── */

    return {

        init: function () {
            var grid = document.getElementById('host-grid');
            if (!grid) return;

            grid.addEventListener('click', function (e) {
                var el = e.target.closest('[data-action]');
                if (!el) return;
                if (el.dataset.action === 'select-host')  onSelect(el.dataset.hostId);
                if (el.dataset.action === 'scan-network') scanNetwork();
            });

            /* Remove-host and unpair-host modal buttons */
            var screen = document.getElementById('screen-hosts');
            if (screen) {
                screen.addEventListener('click', function (e) {
                    var el = e.target.closest('[data-action]');
                    if (!el) return;
                    if (el.dataset.action === 'confirm-remove-host') removeHost(_pendingRemoveId);
                    if (el.dataset.action === 'cancel-remove-host')  App.closeModal();
                    if (el.dataset.action === 'confirm-host-unpair') doUnpair(_pendingUnpairId);
                    if (el.dataset.action === 'cancel-host-unpair')  App.closeModal();
                });
            }

            /* Colour-button shortcuts on a focused host card:
             *   RED  (403) – Remove host from Twilight
             *   YELLOW (405) – Unpair from Sunshine (paired hosts only)    */
            document.addEventListener('keydown', function (e) {
                var active = document.activeElement;
                if (!active || !active.dataset.hostId) return;

                if (e.keyCode === Keys.RED) {
                    e.preventDefault();
                    openRemoveHostModal(active.dataset.hostId);
                } else if (e.keyCode === Keys.YELLOW) {
                    var h = Storage.getHost(active.dataset.hostId);
                    if (h && h.paired) {
                        e.preventDefault();
                        openUnpairModal(active.dataset.hostId);
                    }
                }
            });
        },

        onEnter: function () {
            render();
            Navigation.focusDefault();

            /* Ensure TwilightIdentity is initialised before checking hosts so
             * that uniqueid is available for accurate per-client PairStatus.
             * On first launch there are no hosts, so the delay is moot.
             * On subsequent launches, init() resolves immediately from storage. */
            var runChecks = function () {
                Storage.getHosts().forEach(checkHost);
            };
            if (typeof TwilightIdentity !== 'undefined') {
                if (TwilightIdentity.isReady()) {
                    runChecks();
                } else {
                    TwilightIdentity.init().then(runChecks, runChecks);
                }
            } else {
                runChecks();
            }
        },

        onLeave: function () { /* nothing to clean up */ },

        /** Trigger a Sunshine host network scan via the background service. */
        scanNetwork: scanNetwork,
    };

}());
