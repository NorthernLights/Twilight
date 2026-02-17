'use strict';

/**
 * Twilight - Main Application Controller
 *
 * Responsibilities:
 *   - Screen routing (push/pop stack with animated transitions)
 *   - Modal management
 *   - Toast notifications
 *   - webOS lifecycle integration (back key, deviceInfo, luna services)
 *   - Global key dispatch
 */
var App = (function () {

    var SCREENS = {
        hosts:    HostDiscovery,
        apps:     AppList,
        stream:   null,   // managed inline
        pairing:  Pairing,
        settings: Settings,
    };

    var _stack   = [];          // [{screenId, params}]
    var _current = null;        // active screen id
    var _modal   = false;       // is a modal open?

    /* ── Screen Transitions ── */

    function showScreen(id, params, isBack) {
        var nextEl = document.getElementById('screen-' + id);
        if (!nextEl) { console.error('[App] Unknown screen:', id); return; }

        // Leave current screen
        if (_current) {
            var curEl = document.getElementById('screen-' + _current);
            if (curEl) {
                curEl.classList.remove('active');
                curEl.classList.add(isBack ? 'screen-enter' : 'screen-exit');
                setTimeout(function () { curEl.classList.remove('screen-enter', 'screen-exit'); }, 280);
            }
            var ctrl = SCREENS[_current];
            if (ctrl && ctrl.onLeave) ctrl.onLeave();
        }

        // Enter new screen
        _current = id;
        Navigation.clearFocus();
        nextEl.classList.add('active', isBack ? 'screen-exit' : 'screen-enter');
        setTimeout(function () { nextEl.classList.remove('screen-enter', 'screen-exit'); }, 350);

        var ctrl = SCREENS[id];
        if (ctrl && ctrl.onEnter) {
            // Defer so the DOM is visible before onEnter queries layout
            setTimeout(function () { ctrl.onEnter(params); }, 16);
        }
    }

    /* ── Modal ── */

    function initModals() {
        // "Add Host" submit
        var submitBtn = document.querySelector('[data-action="submit-add-host"]');
        if (submitBtn) {
            submitBtn.addEventListener('click', function () {
                var ip   = (document.getElementById('host-ip-input')   || {}).value || '';
                var name = (document.getElementById('host-name-input') || {}).value || '';
                if (HostDiscovery.addHost(ip, name)) {
                    document.getElementById('host-ip-input').value   = '';
                    document.getElementById('host-name-input').value = '';
                    pub.closeModal();
                }
            });
        }

        // Generic close-modal buttons
        document.querySelectorAll('[data-action="close-modal"]').forEach(function (btn) {
            btn.addEventListener('click', function () { pub.closeModal(); });
        });

        // Backdrop click
        document.querySelectorAll('.modal-backdrop').forEach(function (bd) {
            bd.addEventListener('click', function () { pub.closeModal(); });
        });
    }

    /* ── webOS Integration ── */

    function initWebOS() {
        if (typeof webOS === 'undefined') {
            console.warn('[App] webOS SDK not found – running in browser mode');
            return;
        }

        webOS.deviceInfo(function (info) {
            console.log('[App] Device:', info.modelName, '| webOS', info.version && info.version.major);
        });

        webOS.service.request('luna://com.palm.systemservice', {
            method: 'clock/getTime',
            parameters: {},
            onSuccess: function (r) { console.log('[App] UTC:', r.utc); },
            onFailure: function ()  { /* non-critical */ },
        });

        document.addEventListener('webOSRelaunch', function (e) {
            console.log('[App] Relaunch:', e.detail);
            // Navigate back to home on re-launch
            _stack = [];
            showScreen('hosts', {}, true);
        });

        document.addEventListener('visibilitychange', function () {
            if (document.hidden) {
                console.log('[App] Backgrounded');
                // TODO: pause active stream
            }
        });
    }

    /* ── Exit ── */

    function exitApp() {
        if (typeof webOS !== 'undefined') {
            webOS.service.request('luna://com.webos.service.applicationmanager', {
                method: 'closeByAppId',
                parameters: { id: 'com.twilightstream.client' },
                onSuccess: function () {},
                onFailure: function () { window.close(); },
            });
        } else {
            window.close();
        }
    }

    /* ── Public API ── */

    var pub = {

        init: function () {
            console.log('[App] Twilight v1.0.0 starting');

            HostDiscovery.init();
            AppList.init();
            Pairing.init();
            Settings.init();
            Navigation.init();
            initModals();
            initWebOS();

            // Stream overlay actions
            var resumeBtn = document.querySelector('[data-action="resume-stream"]');
            if (resumeBtn) {
                resumeBtn.addEventListener('click', function () {
                    var overlay = document.getElementById('stream-overlay');
                    if (overlay) overlay.classList.add('hidden');
                });
            }
            var stopBtn = document.querySelector('[data-action="stop-stream"]');
            if (stopBtn) {
                stopBtn.addEventListener('click', function () { pub.goBack(); });
            }

            // Settings button on host screen
            var settingsBtn = document.querySelector('[data-action="settings"]');
            if (settingsBtn) {
                settingsBtn.addEventListener('click', function () { pub.navigate('settings'); });
            }

            // Back buttons
            document.querySelectorAll('[data-action="back"]').forEach(function (btn) {
                btn.addEventListener('click', function () { pub.goBack(); });
            });

            showScreen('hosts', {}, false);
            console.log('[App] Ready');
        },

        /** Push a new screen onto the stack. */
        navigate: function (screenId, params) {
            _stack.push({ screenId: _current, params: {} });
            showScreen(screenId, params || {}, false);
        },

        /** Pop back to the previous screen. */
        goBack: function () {
            if (_modal) { pub.closeModal(); return; }
            if (_stack.length === 0) { exitApp(); return; }
            var prev = _stack.pop();
            showScreen(prev.screenId, prev.params, true);
        },

        /** Handle the hardware BACK key (called by Navigation). */
        handleBack: function () {
            if (_current === 'stream') {
                var overlay = document.getElementById('stream-overlay');
                if (overlay) {
                    var visible = !overlay.classList.contains('hidden');
                    overlay.classList.toggle('hidden', visible);
                    if (!visible) Navigation.focusDefault('btn-resume');
                }
                return;
            }
            pub.goBack();
        },

        /** Handle non-navigation key presses. */
        handleKey: function (/* keyCode */) {
            // Reserved for future: media keys, color buttons, etc.
        },

        /* ── Modals ── */

        openModal: function (id) {
            var modal = document.getElementById('modal-' + id);
            if (!modal) return;
            modal.classList.remove('hidden');
            _modal = true;
            Navigation.setZone(modal);
            // Focus first input if present
            var input = modal.querySelector('.form-input');
            if (input) {
                Navigation.focusEl(input);
                input.focus();
            } else {
                Navigation.focusDefault();
            }
        },

        closeModal: function () {
            document.querySelectorAll('.modal:not(.hidden)').forEach(function (m) {
                m.classList.add('hidden');
            });
            _modal = false;
            Navigation.clearZone();
            Navigation.focusDefault();
        },

        /* ── Toasts ── */

        /**
         * Show a transient notification.
         * @param {string} msg
         * @param {'info'|'success'|'error'|'warning'} [type]
         */
        showToast: function (msg, type) {
            type = type || 'info';
            var c = document.getElementById('toast-container');
            if (!c) return;
            var t = document.createElement('div');
            t.className   = 'toast toast-' + type;
            t.textContent = msg;
            c.appendChild(t);
            setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 3800);
        },
    };

    return pub;

}());

document.addEventListener('DOMContentLoaded', function () { App.init(); });
