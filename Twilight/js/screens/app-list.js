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
 * App List Screen
 *
 * Fetches and displays the list of games/apps from a paired
 * GameStream/Sunshine host.
 *
 * Endpoints used:
 *   App list:    http://<host>:47989/applist
 *   Server info: http://<host>:47989/serverinfo  (to detect running app)
 *   Box art:     https://<host>:47984/appasset?appid=<id>&AssetType=2&AssetIdx=0
 */
var AppList = (function () {

    var GS_HTTP_PORT  = 47989;
    var GS_HTTPS_PORT = 47984;
    var FETCH_TIMEOUT = 10000;

    var _host       = null;
    var _apps       = [];
    var _runningId  = 0;

    /* ── Utilities ── */

    function esc(str) {
        var d = document.createElement('div');
        d.appendChild(document.createTextNode(String(str)));
        return d.innerHTML;
    }

    function fetchText(url, ms) {
        return new Promise(function (resolve, reject) {
            var ctrl  = typeof AbortController !== 'undefined' ? new AbortController() : null;
            var timer = setTimeout(function () {
                if (ctrl) ctrl.abort();
                reject(new Error('timeout'));
            }, ms || FETCH_TIMEOUT);

            fetch(url, ctrl ? { signal: ctrl.signal } : {})
                .then(function (r) { clearTimeout(timer); return r.text(); })
                .then(resolve)
                .catch(function (e) { clearTimeout(timer); reject(e); });
        });
    }

    /* ── XML Parsing ── */

    function parseAppList(xml) {
        var parser = new DOMParser();
        var doc    = parser.parseFromString(xml, 'text/xml');

        /* Sunshine returns status_code="200" on success; anything else means the
         * request was rejected (e.g. pairing pending, unknown uniqueid, server
         * error).  Throw so the caller can show a proper error state rather than
         * the misleading "No Games Found" empty state.                           */
        var root = doc.querySelector('root');
        var code = root ? root.getAttribute('status_code') : null;
        if (code !== null && code !== '200') {
            console.error('[AppList] /applist rejected by host – status_code:', code,
                          '(pairing may be incomplete; ensure pairchallenge succeeded)');
            throw new Error('Host rejected the request (status ' + code + '). ' +
                            'Pairing may be incomplete \u2013 try re-pairing.');
        }

        var nodes  = doc.querySelectorAll('App');
        var apps   = [];
        nodes.forEach(function (n) {
            apps.push({
                id:         parseInt(n.querySelector('ID') ? n.querySelector('ID').textContent : '0', 10),
                name:       n.querySelector('AppTitle') ? n.querySelector('AppTitle').textContent : 'Unknown',
                hdrSupport: n.querySelector('IsHdrSupported') ? n.querySelector('IsHdrSupported').textContent === '1' : false,
            });
        });
        return apps;
    }

    function parseRunningApp(xml) {
        var parser = new DOMParser();
        var doc    = parser.parseFromString(xml, 'text/xml');
        var el     = doc.querySelector('CurrentGame');
        return el ? parseInt(el.textContent, 10) : 0;
    }

    /* ── Data Fetch ── */

    function loadApps() {
        setLoading(true);

        /* Sunshine requires uniqueid to authenticate /applist and return the
         * app list for this specific paired client.  Without it the server
         * either rejects the request or returns an empty response.
         *
         * Wait for identity to be ready (no-op if already initialised – the
         * common case, because App.init() warms it up at startup).           */
        var identityReady = (typeof TwilightIdentity !== 'undefined')
            ? (TwilightIdentity.isReady() ? Promise.resolve() : TwilightIdentity.init())
            : Promise.resolve();

        identityReady.then(function () {
            var uid = (typeof TwilightIdentity !== 'undefined' && TwilightIdentity.isReady())
                ? TwilightIdentity.getUniqueId()
                : null;
            var qs  = uid ? '?uniqueid=' + encodeURIComponent(uid) : '';

            var url = 'http://' + _host.ip + ':' + GS_HTTP_PORT + '/applist' + qs;

            fetchText(url)
                .then(function (xml) {
                    _apps = parseAppList(xml);
                    renderApps();
                    setLoading(false);
                })
                .catch(function (err) {
                    console.error('[AppList] fetch failed:', err);
                    setLoading(false);

                    /* status 404 means Sunshine does not recognise this client as
                     * paired – the pairchallenge likely ran but Sunshine did not
                     * persist the pairing (cert mismatch or stale pending state).
                     * Reset the local paired flag so the home screen will prompt
                     * the user to re-pair rather than looping back here.          */
                    if (_host && err.message && err.message.indexOf('status 404') !== -1) {
                        console.warn('[AppList] 404 from /applist – resetting paired flag for', _host.name);
                        _host.paired = false;
                        Storage.saveHost(_host);
                        App.showToast(
                            'Pairing with \u201c' + _host.name + '\u201d is incomplete\u2014please re-pair.',
                            'warning'
                        );
                        setTimeout(function () { App.goBack(); }, 2800);
                    } else {
                        showError(err && err.message ? err.message : undefined);
                    }
                });

            // Parallel: find currently running app (uniqueid needed for accurate response)
            fetchText('http://' + _host.ip + ':' + GS_HTTP_PORT + '/serverinfo' + qs, 5000)
                .then(function (xml) { _runningId = parseRunningApp(xml); renderApps(); })
                .catch(function () {});
        }).catch(function (err) {
            console.error('[AppList] Identity init failed:', err);
            setLoading(false);
            showError();
        });
    }

    /* ── Render ── */

    function renderApps() {
        var grid  = document.getElementById('app-grid');
        var empty = document.getElementById('apps-empty');
        if (!grid) return;
        grid.innerHTML = '';

        if (_apps.length === 0) {
            if (empty) empty.classList.remove('hidden');
            return;
        }
        if (empty) empty.classList.add('hidden');

        _apps.forEach(function (app) {
            grid.appendChild(makeCard(app));
        });

        Navigation.focusDefault();
    }

    function makeCard(app) {
        var card = document.createElement('div');
        card.className  = 'app-card focusable';
        card.tabIndex   = 0;
        card.dataset.navId = 'app-' + app.id;
        card.dataset.appId = app.id;
        card.dataset.action = 'launch-app';

        var isRunning = (_runningId === app.id);
        var badges = '';
        if (isRunning)     badges += '<span class="badge badge-resume">&#9654; Resume</span>';
        if (app.hdrSupport) badges += '<span class="badge badge-hdr">HDR</span>';

        card.innerHTML =
            '<div class="app-card-art" data-art-id="' + app.id + '"><span>&#127918;</span></div>' +
            '<div class="app-card-info">' +
                '<div class="app-card-name">' + esc(app.name) + '</div>' +
                (badges ? '<div class="app-card-badges">' + badges + '</div>' : '') +
            '</div>';

        // Async box-art load (HTTPS; self-signed cert – may be blocked, gracefully falls back)
        if (_host) {
            var img = new Image();
            img.onload = function () {
                var artEl = document.querySelector('[data-art-id="' + app.id + '"]');
                if (artEl) { artEl.innerHTML = ''; artEl.appendChild(img); }
            };
            img.src = 'https://' + _host.ip + ':' + GS_HTTPS_PORT +
                      '/appasset?appid=' + app.id + '&AssetType=2&AssetIdx=0';
        }

        return card;
    }

    /* ── Unpair ── */

    /**
     * Send a GameStream /unpair request to the host, clear the local paired
     * flag, and navigate back to the host list.
     *
     * The HTTP unpair endpoint does not require TLS, so we use fetch() directly
     * rather than routing through TwilightServices.
     */
    function unpairHost() {
        if (!_host) return;

        var uid = (typeof TwilightIdentity !== 'undefined' && TwilightIdentity.isReady())
            ? TwilightIdentity.getUniqueId()
            : null;

        if (uid) {
            /* Fire-and-forget – the local state update below is authoritative */
            fetch('http://' + _host.ip + ':' + GS_HTTP_PORT +
                  '/unpair?uniqueid=' + encodeURIComponent(uid) +
                  '&devicename=roth'
            ).catch(function () {});
        }

        _host.paired = false;
        Storage.saveHost(_host);

        App.showToast('Unpaired from ' + _host.name, 'info');
        App.closeModal();
        App.goBack();
    }

    /* ── State Helpers ── */

    function setLoading(show) {
        var el   = document.getElementById('apps-loading');
        var grid = document.getElementById('app-grid');
        if (!el) return;
        if (show) { el.classList.remove('hidden'); if (grid) grid.innerHTML = ''; }
        else        el.classList.add('hidden');
    }

    function showError(msg) {
        var el = document.getElementById('apps-empty');
        if (!el) return;
        var h3 = el.querySelector('h3');
        var p  = el.querySelector('p');
        if (h3) h3.textContent = 'Failed to Load Games';
        if (p)  p.textContent  = msg || 'Could not reach host. Check your network connection.';
        el.classList.remove('hidden');
    }

    /* ── Public ── */

    return {

        init: function () {
            var grid = document.getElementById('app-grid');
            if (grid) {
                grid.addEventListener('click', function (e) {
                    var el = e.target.closest('[data-action="launch-app"]');
                    if (!el || !_host) return;
                    var appId = parseInt(el.dataset.appId, 10);
                    var app   = _apps.filter(function (a) { return a.id === appId; })[0];
                    if (app) App.navigate('stream', { host: _host, app: app });
                });
            }

            var refreshBtn = document.querySelector('[data-action="refresh-apps"]');
            if (refreshBtn) {
                refreshBtn.addEventListener('click', function () { if (_host) loadApps(); });
            }

            /* Unpair button – opens confirmation modal */
            var unpairBtn = document.querySelector('[data-action="unpair-host"]');
            if (unpairBtn) {
                unpairBtn.addEventListener('click', function () {
                    var msgEl = document.getElementById('unpair-confirm-msg');
                    if (msgEl && _host) {
                        msgEl.textContent =
                            'Remove Twilight from \u201c' + _host.name +
                            '\u2019s paired clients? You will need to re-pair to use this host.';
                    }
                    App.openModal('unpair-confirm');
                });
            }

            /* Confirm / cancel inside the unpair modal */
            document.addEventListener('click', function (e) {
                var el = e.target.closest('[data-action]');
                if (!el) return;
                if (el.dataset.action === 'confirm-unpair')  unpairHost();
                if (el.dataset.action === 'cancel-unpair')   App.closeModal();
            });
        },

        onEnter: function (params) {
            _host      = params && params.host ? params.host : null;
            _apps      = [];
            _runningId = 0;

            if (_host) {
                var nameEl   = document.getElementById('apps-host-name');
                var statusEl = document.getElementById('apps-host-status');
                if (nameEl)   nameEl.textContent = _host.name;
                if (statusEl) {
                    statusEl.textContent = _host.status === 'online' ? 'Online' : 'Offline';
                    statusEl.className   = 'badge badge-' + (_host.status || 'offline');
                }
                loadApps();
            }
        },

        onLeave: function () {
            _host = null;
            _apps = [];
        },
    };

}());
