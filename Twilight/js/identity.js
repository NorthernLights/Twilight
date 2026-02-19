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
 * TwilightIdentity – Persistent client identity for GameStream pairing.
 *
 * On first run, generates:
 *   • A stable 16-byte unique ID (hex string, sent as &uniqueid= in every request)
 *   • An RSA-2048 key pair
 *   • A minimal self-signed X.509 certificate
 *
 * Everything is stored in localStorage under the 'twilight.identity' key so
 * the same credentials are reused across sessions and app restarts.
 * The private key is stored as a PKCS#8 PEM string; the cert as PEM.
 *
 * webOS localStorage survives app updates but is cleared on app removal.
 *
 * Depends on: TwilightCrypto (js/crypto.js)
 */
var TwilightIdentity = (function () {

    var STORAGE_KEY  = 'twilight.identity';
    var _id          = null;   /* string – 32-char hex */
    var _privateKey  = null;   /* CryptoKey */
    var _pkcs8Pem    = null;   /* string – PKCS#8 PEM, for TLS client auth in pairVerify */
    var _certDer     = null;   /* Uint8Array */
    var _certPem     = null;   /* string */
    var _certSig     = null;   /* Uint8Array – raw sig bytes extracted from cert */
    var _ready       = false;
    var _initPromise = null;   /* cached Promise while init is in-flight */

    /* ── Persistence ── */

    function save(uniqueId, pkcs8Pem, certPem) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify({
                uniqueId: uniqueId,
                pkcs8Pem: pkcs8Pem,
                certPem:  certPem,
            }));
        } catch (e) {
            console.warn('[Identity] Failed to persist identity:', e);
        }
    }

    function load() {
        try {
            var raw = localStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    /* ── Import stored key ── */

    async function importPrivateKey(pkcs8Pem) {
        var der = TwilightCrypto.pemToBytes(pkcs8Pem);
        return window.crypto.subtle.importKey(
            'pkcs8', der,
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            true, ['sign']
        );
    }

    /* ── Public ── */

    return {

        /**
         * Initialise identity.  Must be awaited before any pairing call.
         *
         * Re-entrant safe: if two callers invoke init() before the first has
         * finished (e.g. App startup + HostDiscovery both calling concurrently),
         * the second caller receives the same in-flight Promise so only one
         * key-generation / key-import ever runs.  This prevents two concurrent
         * inits from generating conflicting identities and overwriting each
         * other's _id / _certPem mid-pairing-handshake.
         */
        init: function () {
            if (_ready) return Promise.resolve();
            if (_initPromise) return _initPromise;

            _initPromise = (async function () {
                var stored = load();

                if (stored && stored.uniqueId && stored.pkcs8Pem && stored.certPem) {
                    /* Restore from localStorage */
                    try {
                        _id         = stored.uniqueId;
                        _pkcs8Pem   = stored.pkcs8Pem;
                        _certPem    = stored.certPem;
                        _certDer    = TwilightCrypto.pemToBytes(_certPem);
                        _certSig    = TwilightCrypto.parseCertSignature(_certDer);
                        _privateKey = await importPrivateKey(stored.pkcs8Pem);
                        _ready = true;
                        console.log('[Identity] Loaded from storage, uid:', _id);
                        return;
                    } catch (e) {
                        console.warn('[Identity] Stored identity corrupt, regenerating:', e);
                    }
                }

                /* Generate fresh identity */
                console.log('[Identity] Generating new RSA-2048 identity\u2026');
                var uid = TwilightCrypto.bytesToHex(TwilightCrypto.randomBytes(16));

                var identity = await TwilightCrypto.generateKeyAndCert();

                /* Export private key as PKCS#8 PEM for storage */
                var pkcs8Der = new Uint8Array(
                    await window.crypto.subtle.exportKey('pkcs8', identity.privateKey)
                );
                var pkcs8Pem = TwilightCrypto.bytesToPem(pkcs8Der, 'PRIVATE KEY');

                _id         = uid;
                _pkcs8Pem   = pkcs8Pem;
                _privateKey = identity.privateKey;
                _certDer    = identity.certDer;
                _certPem    = identity.certPem;
                _certSig    = identity.certSig;
                _ready      = true;

                save(uid, pkcs8Pem, _certPem);
                console.log('[Identity] Generated new identity, uid:', _id);
            }());

            return _initPromise;
        },

        /** 32-hex-char unique device ID, sent as &uniqueid= in every request. */
        getUniqueId: function () { return _id; },

        /**
         * Hex-encoded UTF-8 bytes of the PEM certificate string.
         *
         * NOTE: GameStream/Sunshine expects &clientcert= = hex(DER bytes), NOT
         * hex(PEM text).  Use TwilightCrypto.bytesToHex(getCertDer()) when
         * building the clientcert query parameter for the /pair endpoint.
         */
        getCertPemHex: function () {
            return TwilightCrypto.bytesToHex(new TextEncoder().encode(_certPem));
        },

        /** DER bytes of the client certificate. */
        getCertDer: function () { return _certDer; },

        /** PEM string of the client certificate. */
        getCertPem: function () { return _certPem; },

        /**
         * Raw RSA signature bytes extracted from the client's X.509 certificate.
         * Equivalent to what OpenSSL's X509_get0_signature() returns.
         * Used in the pairing challenge response.
         */
        getCertSignature: function () { return _certSig; },

        /** The RSA-2048 private key CryptoKey (for signing during pairing). */
        getPrivateKey: function () { return _privateKey; },

        /**
         * PKCS#8 PEM string of the private key.
         * Passed to TwilightServices so it can present the client certificate
         * in the TLS handshake for the Step 5 pairchallenge HTTPS request.
         * Sunshine verifies this cert matches the one registered in Step 1.
         */
        getPrivateKeyPem: function () { return _pkcs8Pem; },

        /** True once init() has completed successfully. */
        isReady: function () { return _ready; },

        /**
         * Wipe the stored identity and force re-generation on next init().
         * Call this if pairing state is fully reset.
         */
        reset: function () {
            localStorage.removeItem(STORAGE_KEY);
            _id = _privateKey = _pkcs8Pem = _certDer = _certPem = _certSig = null;
            _ready = false;
            _initPromise = null;   /* allow a clean re-init after reset */
            console.log('[Identity] Identity wiped');
        },
    };

}());
