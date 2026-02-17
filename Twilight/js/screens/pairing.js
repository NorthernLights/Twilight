'use strict';

/**
 * Pairing Screen
 *
 * Displays a 4-digit PIN and drives the Moonlight/GameStream pairing
 * handshake with the host.
 *
 * NOTE: Full cryptographic pairing (RSA key exchange, certificate pinning,
 * AES-CBC challenge) is stubbed here and marked TODO. The UI flow is complete
 * so the crypto layer can be dropped in without changing the screen logic.
 *
 * Pairing flow overview (GameStream / Sunshine):
 *   1. Client generates random PIN + RSA-2048 key pair + self-signed cert
 *   2. GET /pair?devicename=...&updateState=1&phrase=getservercert&salt=...&clientcert=...
 *   3. Server shows PIN to user; user enters it
 *   4. Client polls GET /pair?...&phrase=pairchallenge  until paired
 *   5. On success, server returns paired=1
 */
var Pairing = (function () {

    var TIMEOUT_MS  = 60000;  // 60 s total pairing window
    var POLL_MS     = 2500;   // poll every 2.5 s
    var GS_HTTP_PORT = 47989;

    var _host      = null;
    var _pin       = null;
    var _active    = false;
    var _timerId   = null;
    var _pollId    = null;
    var _startedAt = 0;

    /* ── PIN ── */

    function generatePin() {
        return String(Math.floor(1000 + Math.random() * 9000));
    }

    function showPin(pin) {
        var digits = document.querySelectorAll('.pin-digit');
        pin.split('').forEach(function (ch, i) {
            if (digits[i]) {
                digits[i].textContent = '-';
                digits[i].classList.remove('lit');
                // Stagger reveal
                (function (idx) {
                    setTimeout(function () {
                        if (digits[idx]) {
                            digits[idx].textContent = ch;
                            digits[idx].classList.add('lit');
                        }
                    }, idx * 160);
                }(i));
            }
        });
    }

    /* ── Timeout bar ── */

    function startBar() {
        var fill = document.getElementById('timeout-fill');
        if (!fill) return;
        fill.style.transition = 'none';
        fill.style.width      = '100%';
        // Next frame: start shrinking
        requestAnimationFrame(function () {
            requestAnimationFrame(function () {
                fill.style.transition = 'width ' + TIMEOUT_MS + 'ms linear';
                fill.style.width      = '0%';
            });
        });
    }

    /* ── Status text ── */

    function setStatus(msg) {
        var p = document.querySelector('#pairing-status-msg');
        if (p) p.textContent = msg;
    }

    /* ── Pairing protocol stubs ── */

    /**
     * TODO: Implement full GameStream pairing crypto.
     *
     * Steps required:
     *   1. Generate RSA-2048 key pair via WebCrypto API
     *   2. Build self-signed X.509 cert (DER-encoded)
     *   3. Derive salt from PIN using SHA-256
     *   4. GET /pair?phrase=getservercert&salt=<hex>&clientcert=<hex-DER>
     *   5. Parse server's cert from XML response
     *   6. GET /pair?phrase=pairchallenge
     *   7. Decrypt server challenge, re-encrypt, send back
     *   8. GET /pair?phrase=clientchallenge&...
     *   9. Verify and complete
     *
     * Until crypto is implemented, we show the PIN and let the user
     * manually confirm on the host (e.g., via Sunshine web UI).
     */
    function beginPairing(host, pin) {
        setStatus('Enter PIN on your host, then press OK in Sunshine / GameStream.');
        console.log('[Pairing] PIN for', host.ip, ':', pin);

        // TODO: replace with real HTTP pairing call
        // startCryptoHandshake(host, pin);
    }

    /* ── Completion handlers ── */

    function onSuccess() {
        cleanup();
        if (_host) {
            _host.paired = true;
            _host.status = 'online';
            Storage.saveHost(_host);
            App.showToast('Paired with ' + _host.name, 'success');
            App.navigate('apps', { host: _host });
        }
    }

    function onFailed(reason) {
        cleanup();
        App.showToast('Pairing failed' + (reason ? ': ' + reason : ''), 'error');
        App.goBack();
    }

    function onTimeout() {
        cleanup();
        App.showToast('Pairing timed out', 'warning');
        App.goBack();
    }

    function cleanup() {
        _active = false;
        if (_timerId) { clearTimeout(_timerId); _timerId = null; }
        if (_pollId)  { clearTimeout(_pollId);  _pollId  = null; }
    }

    /* ── Public ── */

    return {

        init: function () {
            // Both "cancel" buttons share the same data-action
            document.addEventListener('click', function (e) {
                var el = e.target.closest('[data-action="cancel-pairing"]');
                if (el && document.getElementById('screen-pairing').classList.contains('active')) {
                    cleanup();
                    App.goBack();
                }
            });
        },

        onEnter: function (params) {
            _host      = params && params.host ? params.host : null;
            _pin       = generatePin();
            _active    = true;
            _startedAt = Date.now();

            if (_host) {
                var nameEl = document.getElementById('pairing-host-name');
                if (nameEl) nameEl.textContent = _host.name;
            }

            showPin(_pin);
            startBar();
            beginPairing(_host, _pin);

            _timerId = setTimeout(onTimeout, TIMEOUT_MS);
            Navigation.focusDefault('btn-cancel-pairing');
        },

        onLeave: function () {
            cleanup();
        },

        /** External call: mark pairing as confirmed (for future HTTP poll completion). */
        confirm: function () {
            if (_active && _host) onSuccess();
        },

        /** External call: mark pairing as failed. */
        fail: function (reason) {
            if (_active) onFailed(reason);
        },
    };

}());
