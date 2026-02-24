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
 * Pairing Screen – full GameStream / Sunshine pairing protocol.
 *
 * Protocol reference: moonlight-qt/app/backend/nvpairingmanager.cpp
 *
 * ┌─────┬──────────────────────────────────────────────────────────────────┐
 * │Step │ Description                                                      │
 * ├─────┼──────────────────────────────────────────────────────────────────┤
 * │  1  │ GET /pair?phrase=getservercert&salt=…&clientcert=…               │
 * │     │ Server returns its X.509 certificate (hex-PEM in <plaincert>).   │
 * ├─────┼──────────────────────────────────────────────────────────────────┤
 * │  2  │ GET /pair?clientchallenge=<AES-ECB(randomChallenge)>             │
 * │     │ Server returns <challengeresponse> encrypted with the same key.  │
 * ├─────┼──────────────────────────────────────────────────────────────────┤
 * │  3  │ Decrypt challenge response.                                      │
 * │     │ Build: serverChallenge || clientCertSig || clientSecret          │
 * │     │ GET /pair?serverchallengeresp=<AES-ECB(SHA256(above))>           │
 * │     │ Server returns <pairingsecret> = serverSecret || RSA-sig.        │
 * ├─────┼──────────────────────────────────────────────────────────────────┤
 * │  4  │ Verify server's RSA signature over serverSecret.                 │
 * │     │ Verify PIN: SHA256(randomChallenge||serverCertSig||serverSecret) │
 * │     │   must equal serverResponse (first 32 bytes of step-2 decrypt).  │
 * │     │ GET /pair?clientpairingsecret=<clientSecret||RSA-sign(clientSecret)>│
 * ├─────┼──────────────────────────────────────────────────────────────────┤
 * │  5  │ GET https://<host>:47984/pair?phrase=pairchallenge               │
 * │     │ Server confirms pairing over HTTPS.                              │
 * └─────┴──────────────────────────────────────────────────────────────────┘
 *
 * AES key: SHA-256(salt || pin_utf8)[0:16]   (Gen 7+ / Sunshine = SHA-256)
 * AES mode: ECB, no padding (simulated via TwilightCrypto.aesEcbEncrypt/Decrypt).
 *
 * Depends on: TwilightCrypto (js/crypto.js), TwilightIdentity (js/identity.js)
 */
var Pairing = (function () {

    /* ── Constants ── */
    var GS_HTTP_PORT  = 47989;
    var GS_HTTPS_PORT = 47984;
    var TIMEOUT_MS    = 180000;  /* 3 minutes – starts only after identity is ready */
    var DEVICE_NAME   = 'roth';  /* Moonlight sends "roth" as the devicename */

    /* ── State ── */
    var _host    = null;
    var _pin     = null;
    var _active  = false;
    var _timerId = null;

    /* ══════════════════════════════════════════
       UI helpers
       ══════════════════════════════════════════ */

    function showPin(pin) {
        var digits = document.querySelectorAll('.pin-digit');
        pin.split('').forEach(function (ch, i) {
            if (!digits[i]) return;
            digits[i].textContent = '-';
            digits[i].classList.remove('lit');
            (function (idx) {
                setTimeout(function () {
                    if (digits[idx]) {
                        digits[idx].textContent = ch;
                        digits[idx].classList.add('lit');
                    }
                }, idx * 160);
            }(i));
        });
    }

    function startBar() {
        var fill = document.getElementById('timeout-fill');
        if (!fill) return;
        fill.style.transition = 'none';
        fill.style.width = '100%';
        requestAnimationFrame(function () {
            requestAnimationFrame(function () {
                fill.style.transition = 'width ' + TIMEOUT_MS + 'ms linear';
                fill.style.width = '0%';
            });
        });
    }

    function setStatus(msg) {
        var p = document.getElementById('pairing-status-msg');
        if (p) p.textContent = msg;
        console.log('[Pairing]', msg);
    }

    /* ══════════════════════════════════════════
       XML helpers
       ══════════════════════════════════════════ */

    function parseXml(text) {
        return new DOMParser().parseFromString(text, 'text/xml');
    }

    function xmlStr(doc, tag) {
        var el = doc.querySelector(tag);
        return el ? el.textContent.trim() : null;
    }

    function xmlHex(doc, tag) {
        var s = xmlStr(doc, tag);
        return s ? TwilightCrypto.hexToBytes(s) : null;
    }

    function checkStatus(doc, step) {
        var root = doc.querySelector('root');
        var code = root ? root.getAttribute('status_code') : null;
        if (code !== '200') {
            throw new Error('Step ' + step + ': server returned status_code ' + code);
        }
    }

    /* ══════════════════════════════════════════
       HTTP helpers
       ══════════════════════════════════════════ */

    function fetchXml(url, ms) {
        return new Promise(function (resolve, reject) {
            var ctrl  = typeof AbortController !== 'undefined' ? new AbortController() : null;
            var timer = setTimeout(function () {
                if (ctrl) ctrl.abort();
                reject(new Error('Timed out: ' + url));
            }, ms || 8000);

            fetch(url, ctrl ? { signal: ctrl.signal } : {})
                .then(function (r) {
                    clearTimeout(timer);
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    return r.text();
                })
                .then(function (txt) { resolve(parseXml(txt)); })
                .catch(function (e)  { clearTimeout(timer); reject(e); });
        });
    }

    function buildUrl(scheme, ip, port, path, params) {
        var qs = Object.keys(params).map(function (k) {
            return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
        }).join('&');
        return scheme + '://' + ip + ':' + port + '/' + path + '?' + qs;
    }

    function pairUrl(ip, extra) {
        var params = {
            uniqueid:    TwilightIdentity.getUniqueId(),
            devicename:  DEVICE_NAME,
            updateState: '1',
        };
        Object.keys(extra).forEach(function (k) { params[k] = extra[k]; });
        return buildUrl('http', ip, GS_HTTP_PORT, 'pair', params);
    }

    function sendUnpair(ip) {
        /* Fire-and-forget cleanup on any failure path */
        fetch(buildUrl('http', ip, GS_HTTP_PORT, 'unpair', {
            uniqueid:   TwilightIdentity.getUniqueId(),
            devicename: DEVICE_NAME,
        })).catch(function () {});
    }

    /* ══════════════════════════════════════════
       Core pairing protocol (async)
       ══════════════════════════════════════════ */

    async function doPairing(host, pin) {
        var ip = host.ip;

        /* ── Pre-pair cleanup ───────────────────────────────────────────────
         * Fire-and-forget /unpair for this uniqueid before starting the
         * handshake.  If a previous pairing attempt left Sunshine with a
         * stale "pending" state for this uid, the new step 1 may conflict.
         * The call is non-fatal; it silently succeeds or is ignored by
         * Sunshine if no such entry exists.                                  */
        fetch(buildUrl('http', ip, GS_HTTP_PORT, 'unpair', {
            uniqueid:   TwilightIdentity.getUniqueId(),
            devicename: DEVICE_NAME,
        })).catch(function () {});

        /* ── AES key derivation ─────────────────
           aesKey = SHA-256(salt || pin_utf8)[0:16]   */
        var salt      = TwilightCrypto.randomBytes(16);
        var pinBytes  = new TextEncoder().encode(pin);
        var saltedPin = new Uint8Array(salt.length + pinBytes.length);
        saltedPin.set(salt, 0);
        saltedPin.set(pinBytes, salt.length);
        var aesKey = (await TwilightCrypto.sha256(saltedPin)).slice(0, 16);

        /* ── Step 1: getservercert ────────────── */
        setStatus('Step 1/5  Fetching server certificate…');
        /* Sunshine's pairing handler calls PEM_read_bio_X509() on the
         * hex-decoded clientcert bytes, so it expects hex(PEM text) –
         * i.e. hex( UTF-8 bytes of "-----BEGIN CERTIFICATE-----\n…" ).
         * TwilightIdentity.getCertPemHex() produces exactly this format. */
        var s1 = await fetchXml(pairUrl(ip, {
            phrase:     'getservercert',
            salt:       TwilightCrypto.bytesToHex(salt),
            clientcert: TwilightIdentity.getCertPemHex(),
        }), 30000);
        checkStatus(s1, 1);
        if (xmlStr(s1, 'paired') !== '1') throw new Error('Step 1: server refused pairing');

        var serverCertPemBytes = xmlHex(s1, 'plaincert');
        if (!serverCertPemBytes) {
            sendUnpair(ip);
            throw new Error('Step 1: no plaincert (server may already be pairing)');
        }
        var serverCertPem = new TextDecoder().decode(serverCertPemBytes);
        var serverCertDer = TwilightCrypto.pemToBytes(serverCertPem);

        /* ── Step 2: clientchallenge ──────────── */
        /*
         * Sunshine shows a PIN-entry dialog on the host when it receives this
         * request, then blocks until the user types the PIN shown on Twilight
         * and clicks OK.  This step can legitimately take the full TIMEOUT_MS.
         */
        setStatus('Step 2/5  Enter the PIN on your Sunshine host now…');
        var randomChallenge = TwilightCrypto.randomBytes(16);
        var encChallenge    = await TwilightCrypto.aesEcbEncrypt(aesKey, randomChallenge);
        var s2 = await fetchXml(pairUrl(ip, {
            clientchallenge: TwilightCrypto.bytesToHex(encChallenge),
        }), TIMEOUT_MS);
        checkStatus(s2, 2);
        if (xmlStr(s2, 'paired') !== '1') { sendUnpair(ip); throw new Error('Step 2 refused'); }

        var encResp   = xmlHex(s2, 'challengeresponse');
        var respData  = await TwilightCrypto.aesEcbDecrypt(aesKey, encResp);
        /* Layout (SHA-256, hashLength = 32):
             [0 …31] serverResponse  – hash verified in step 4
             [32…47] serverChallenge – 16-byte server nonce               */
        var serverResponse  = respData.slice(0, 32);
        var serverChallenge = respData.slice(32, 48);

        /* ── Step 3: serverchallengeresp ─────── */
        setStatus('Step 3/5  Answering server challenge…');
        var clientSecret  = TwilightCrypto.randomBytes(16);
        var clientCertSig = TwilightIdentity.getCertSignature();

        /* challengeInput = serverChallenge || clientCertSig || clientSecret */
        var challengeInput = new Uint8Array(
            serverChallenge.length + clientCertSig.length + clientSecret.length
        );
        challengeInput.set(serverChallenge, 0);
        challengeInput.set(clientCertSig,   serverChallenge.length);
        challengeInput.set(clientSecret,    serverChallenge.length + clientCertSig.length);

        var challengeHash    = await TwilightCrypto.sha256(challengeInput);  /* 32 bytes */
        var encChallengeHash = await TwilightCrypto.aesEcbEncrypt(aesKey, challengeHash);

        var s3 = await fetchXml(pairUrl(ip, {
            serverchallengeresp: TwilightCrypto.bytesToHex(encChallengeHash),
        }), 30000);
        checkStatus(s3, 3);
        if (xmlStr(s3, 'paired') !== '1') { sendUnpair(ip); throw new Error('Step 3 refused'); }

        var pairingSecretRaw = xmlHex(s3, 'pairingsecret');
        var serverSecret     = pairingSecretRaw.slice(0, 16);
        var serverSignature  = pairingSecretRaw.slice(16);

        /* ── Step 4: verify + clientpairingsecret */
        setStatus('Step 4/5  Verifying server identity…');

        /* 4a. Verify server signed serverSecret with its private key */
        var sigOk = await TwilightCrypto.rsaVerify(serverSecret, serverSignature, serverCertDer);
        if (!sigOk) {
            sendUnpair(ip);
            throw new Error('MITM attack detected: server signature invalid');
        }

        /* 4b. Verify PIN:
               SHA256(randomChallenge || serverCertSig || serverSecret) == serverResponse */
        var serverCertSig  = TwilightCrypto.parseCertSignature(serverCertDer);
        var pinInput       = new Uint8Array(
            randomChallenge.length + serverCertSig.length + serverSecret.length
        );
        pinInput.set(randomChallenge, 0);
        pinInput.set(serverCertSig,   randomChallenge.length);
        pinInput.set(serverSecret,    randomChallenge.length + serverCertSig.length);

        var pinHash  = await TwilightCrypto.sha256(pinInput);
        var pinMatch = (pinHash.length === serverResponse.length) &&
            pinHash.every(function (b, i) { return b === serverResponse[i]; });
        if (!pinMatch) {
            sendUnpair(ip);
            throw new Error('PIN incorrect');
        }

        /* 4c. Send clientPairingSecret = clientSecret || RSA-sign(clientSecret) */
        setStatus('Step 4/5  Sending client pairing secret…');
        var clientSig     = await TwilightCrypto.rsaSign(clientSecret, TwilightIdentity.getPrivateKey());
        var clientSecret_ = new Uint8Array(clientSecret.length + clientSig.length);
        clientSecret_.set(clientSecret, 0);
        clientSecret_.set(clientSig,    clientSecret.length);

        var s4 = await fetchXml(pairUrl(ip, {
            clientpairingsecret: TwilightCrypto.bytesToHex(clientSecret_),
        }), 30000);
        checkStatus(s4, 4);
        if (xmlStr(s4, 'paired') !== '1') { sendUnpair(ip); throw new Error('Step 4 refused'); }

        /* ── Step 5: HTTPS pairchallenge ─────────────────────────────────
         *
         * Sunshine/Vibeshine requires a mutual-TLS HTTPS request to port 47984
         * to PERSIST the pairing to its client database.  Without a successful
         * pairchallenge the device stays in a transient "pending" state and
         * subsequent /applist requests receive status 404.
         *
         * The server presents its TLS cert (self-signed in stock Sunshine;
         * Let's Encrypt-signed in Vibeshine) and verifies the client presents
         * the cert registered in step 1.
         *
         * Problem with direct fetch() in Chrome/webOS:
         *   • Self-signed cert  → rejected by browser (untrusted CA)
         *   • Let's Encrypt cert on Vibeshine → cert is browser-trusted, but
         *     is issued for a domain name, not an IP address.  Connecting via
         *     IP causes ERR_CERT_COMMON_NAME_INVALID.  Both cases fail.
         *
         * Primary path: Luna pairVerify via TwilightServices (Node.js with
         *   rejectUnauthorized: false + checkServerIdentity bypass; the
         *   client cert is still presented for Sunshine's mutual-TLS auth).
         *   TwilightServices MUST be installed on this device.
         *
         * Fallback: direct HTTPS fetch (works only without cert issues; kept
         *   as a dev-mode / simulator convenience path).
         *
         * If both paths fail: pairing FAILS.  The error is surfaced to the
         *   user so they know to install/restart TwilightServices.             */
        setStatus('Step 5/5  Confirming pairing over HTTPS\u2026');

        var pairChallengeParams = {
            uniqueid:    TwilightIdentity.getUniqueId(),
            devicename:  DEVICE_NAME,
            updateState: '1',
            phrase:      'pairchallenge',
        };

        var s5 = null;
        var s5Error = null;

        /* Luna pairVerify via TwilightServices.
         *
         * Two calls are made in sequence:
         *
         *   storePairingCert – Writes the client cert + private key to temp
         *     files inside TwilightServices (mirrors moonlight-tv storing
         *     client.pem / key.pem on disk for libcurl CURLOPT_SSLCERT /
         *     CURLOPT_SSLKEY).  Failure is non-fatal; pairVerify falls back
         *     to inline parameters supplied in the second call.
         *
         *   pairVerify – Performs the HTTPS pairchallenge using tls.connect()
         *     directly (mirrors moonlight-tv's libcurl mutual-TLS flow).
         *     A TCP probe runs first to distinguish network failures from TLS
         *     failures.                                                         */
        if (typeof webOS !== 'undefined' && webOS.service) {
            /* ── storePairingCert ────────────────────────────────────────── */
            await new Promise(function (resolve) {
                var done  = false;
                var timer = setTimeout(function () {
                    if (!done) { done = true; resolve(); }
                }, 5000);
                webOS.service.request('luna://com.twilightstream.client.service', {
                    method:     'storePairingCert',
                    parameters: {
                        certPem: TwilightIdentity.getCertPem(),
                        keyPem:  TwilightIdentity.getPrivateKeyPem(),
                    },
                    onSuccess: function () {
                        clearTimeout(timer);
                        if (!done) {
                            done = true;
                            console.log('[Pairing] Step 5: cert/key stored in TwilightServices');
                            resolve();
                        }
                    },
                    onFailure: function (err) {
                        clearTimeout(timer);
                        if (!done) {
                            done = true;
                            /* Non-fatal: pairVerify uses inline cert/key fallback */
                            console.warn('[Pairing] Step 5: storePairingCert failed '
                                + '(will use inline params):', err && err.errorText);
                            resolve();
                        }
                    },
                });
            });

            /* ── pairVerify ──────────────────────────────────────────────── */
            try {
                s5 = await new Promise(function (resolve, reject) {
                    var settled = false;
                    var timer = setTimeout(function () {
                        if (!settled) { settled = true; reject(new Error('Step 5: service call timed out')); }
                    }, 15000);

                    webOS.service.request('luna://com.twilightstream.client.service', {
                        method:     'pairVerify',
                        parameters: {
                            ip:      ip,
                            port:    GS_HTTPS_PORT,
                            params:  pairChallengeParams,
                            /* certPem / keyPem are fallback for older TwilightServices
                             * builds that don't have storePairingCert.  The new service
                             * reads from the temp files written above instead.         */
                            certPem: TwilightIdentity.getCertPem(),
                            keyPem:  TwilightIdentity.getPrivateKeyPem(),
                        },
                        onSuccess: function (res) {
                            clearTimeout(timer);
                            if (settled) return;
                            settled = true;
                            if (!res.xml) { reject(new Error('pairVerify: no XML returned')); return; }
                            console.log('[Pairing] Step 5: pairVerify service OK → xml:',
                                res.xml.slice(0, 120));
                            resolve(parseXml(res.xml));
                        },
                        onFailure: function (err) {
                            clearTimeout(timer);
                            if (settled) return;
                            settled = true;
                            reject(new Error((err && err.errorText) || 'pairVerify service failed'));
                        },
                    });
                });
            } catch (e) {
                s5Error = e;
                console.warn('[Pairing] Step 5 Luna pairVerify failed:', e.message);
            }
        }

        if (s5) {
            /* Validate the pairchallenge response */
            checkStatus(s5, 5);
            if (xmlStr(s5, 'paired') !== '1') {
                sendUnpair(ip);
                throw new Error('Step 5 (HTTPS) refused');
            }
            console.log('[Pairing] Step 5: pairchallenge confirmed – paired = 1');
        } else {
            /* Luna pairVerify path failed – pairing cannot complete.
             *
             * Sunshine/Vibeshine persists the device to its client database
             * ONLY after a successful pairchallenge (step 5) with mutual TLS.
             * Without it, /applist returns status 404 and the device stays pending.
             *
             * Common causes:
             *   • TwilightServices not installed/running on this device
             *     or Simulator build (build and install the .ipk)
             *   • TLS configuration mismatch (cipher, protocol version)
             *   • Vibeshine Let's Encrypt cert – Luna path uses
             *     rejectUnauthorized: false to bypass hostname check          */
            throw new Error(
                'Pairing step 5 (HTTPS pairchallenge) failed' +
                (s5Error ? ': ' + s5Error.message : '') +
                '.\nEnsure TwilightServices is installed and running.' +
                ' If it is running, try Settings \u2192 About \u2192 Reset Pairing Identity, then re-pair.'
            );
        }
        /* Pairing complete! */
    }

    /* ══════════════════════════════════════════
       Outcome handlers
       ══════════════════════════════════════════ */

    function onSuccess() {
        cleanup();
        if (!_host) return;
        _host.paired = true;
        _host.status = 'online';
        Storage.saveHost(_host);
        App.showToast('Paired with ' + _host.name, 'success');
        /* Use replace() so the pairing screen is removed from the back stack.
         * Pressing BACK from the app list will return to the host list, not
         * the PIN screen.                                                     */
        App.replace('apps', { host: _host });
    }

    function onFailed(err) {
        cleanup();
        var msg = err && err.message ? err.message : String(err);
        console.error('[Pairing] Error:', msg);
        var toast = (msg.indexOf('PIN') !== -1)
            ? 'Wrong PIN – please try again'
            : 'Pairing failed: ' + msg;
        App.showToast(toast, 'error');
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
    }

    /* ══════════════════════════════════════════
       Public screen API
       ══════════════════════════════════════════ */

    return {

        init: function () {
            document.addEventListener('click', function (e) {
                var el = e.target.closest('[data-action="cancel-pairing"]');
                if (!el) return;
                var screen = document.getElementById('screen-pairing');
                if (!screen || !screen.classList.contains('active')) return;
                cleanup();
                App.goBack();
            });
        },

        onEnter: function (params) {
            _host   = params && params.host ? params.host : null;
            _active = true;

            /* Show host name */
            if (_host) {
                var nameEl = document.getElementById('pairing-host-name');
                if (nameEl) nameEl.textContent = _host.name;
            }

            /* Generate and display PIN immediately so the user can read it
               while identity initialisation runs in the background.        */
            _pin = String(Math.floor(1000 + Math.random() * 9000));
            showPin(_pin);
            setStatus('Preparing secure identity\u2026');

            /* Ensure identity ready, then start pairing protocol.
               The watchdog timer and progress bar start only once identity is
               ready – this ensures RSA-2048 key generation on first run (which
               can take 10-30 s on slow hardware) does not consume the pairing
               budget before the handshake even begins.                       */
            var identityReady = TwilightIdentity.isReady()
                ? Promise.resolve()
                : TwilightIdentity.init();

            identityReady
                .then(function () {
                    if (!_active || !_host) return;
                    /* Pairing protocol is about to start: begin the timer */
                    startBar();
                    _timerId = setTimeout(onTimeout, TIMEOUT_MS);
                    setStatus('Step 1/5  Connecting to host\u2026');
                    return doPairing(_host, _pin);
                })
                .then(function () {
                    if (_active) onSuccess();
                })
                .catch(function (e) {
                    if (_active) onFailed(e);
                });

            Navigation.focusDefault('btn-cancel-pairing');
        },

        onLeave: function () {
            cleanup();
        },
    };

}());
