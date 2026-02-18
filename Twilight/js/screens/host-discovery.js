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

    var GS_HTTP_PORT  = 47989;
    var CHECK_TIMEOUT = 5000;  // ms

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

        // Remove old host cards but keep the "Add" and "Scan" action cards
        Array.prototype.forEach.call(
            grid.querySelectorAll('.host-card:not(.host-card-add):not(.host-card-scan)'),
            function (c) { c.remove(); }
        );

        var addCard = grid.querySelector('.host-card-add');
        hosts.forEach(function (host) {
            grid.insertBefore(renderHostCard(host), addCard);
        });

        if (empty) empty.classList.toggle('hidden', hosts.length > 0);
    }

    /* ── Status Check ── */

    function checkHost(host) {
        var url = 'http://' + host.ip + ':' + GS_HTTP_PORT + '/serverinfo';

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
                    var pairEl     = doc.querySelector('PairStatus');
                    host.status = 'online';
                    host.paired = pairEl ? pairEl.textContent === '1' : false;
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
        var dot  = card.querySelector('.host-status-dot');
        var lbl  = card.querySelector('.host-status-label');
        var st   = host.status || 'unknown';
        if (dot) dot.className = 'host-status-dot ' + st;
        if (lbl) { lbl.textContent = statusLabel(st); lbl.className = 'host-status-label ' + st; }
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

    /* ── Network Scan ── */

    /**
     * Trigger a Sunshine/GameStream host discovery scan via the Twilight
     * background service (com.twilightstream.client.service).
     * Discovered hosts that are not already saved are added automatically.
     */
    function scanNetwork() {
        if (typeof webOS === 'undefined') {
            App.showToast('Network scan requires webOS', 'warning');
            return;
        }

        var scanCard  = document.querySelector('[data-action="scan-network"]');
        var scanLabel = scanCard && scanCard.querySelector('.scan-label');

        if (scanCard) scanCard.classList.add('scanning');
        if (scanLabel) scanLabel.textContent = 'Scanning\u2026';
        App.showToast('Scanning for Sunshine hosts\u2026', 'info');

        webOS.service.request('luna://com.twilightstream.client.service', {
            method:     'scan',
            parameters: { timeout: 5000 },
            onSuccess: function (result) {
                if (scanCard)  scanCard.classList.remove('scanning');
                if (scanLabel) scanLabel.textContent = 'Scan Network';

                var found   = 0;
                var already = 0;

                (result.hosts || []).forEach(function (discovered) {
                    var existing = Storage.getHosts();
                    if (existing.some(function (h) { return h.ip === discovered.ip; })) {
                        already++;
                        return;
                    }
                    var host = Storage.createHost(discovered.ip, discovered.name);
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
                        'No new hosts found (' + already + ' already added)',
                        'info'
                    );
                } else {
                    App.showToast('No Sunshine hosts found on this network', 'warning');
                }
            },
            onFailure: function (err) {
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
                if (el.dataset.action === 'add-host')     App.openModal('add-host');
                if (el.dataset.action === 'scan-network') scanNetwork();
            });
        },

        onEnter: function () {
            render();
            Storage.getHosts().forEach(checkHost);
            Navigation.focusDefault();
        },

        onLeave: function () { /* nothing to clean up */ },

        /** Trigger a Sunshine host network scan via the background service. */
        scanNetwork: scanNetwork,

        /** Called from the "Add Host" modal. */
        addHost: function (ip, name) {
            if (!ip || !ip.trim()) {
                App.showToast('Please enter a host IP address', 'error');
                return false;
            }
            var hosts = Storage.getHosts();
            if (hosts.some(function (h) { return h.ip === ip.trim(); })) {
                App.showToast('A host with that IP already exists', 'warning');
                return false;
            }
            var host = Storage.createHost(ip, name);
            Storage.saveHost(host);
            render();
            checkHost(host);
            App.showToast('Host added: ' + host.name, 'success');
            return true;
        },
    };

}());
