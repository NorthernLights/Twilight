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

    var STORAGE_KEY = 'twilight.identity';
    var _id         = null;   /* string – 32-char hex */
    var _privateKey = null;   /* CryptoKey */
    var _certDer    = null;   /* Uint8Array */
    var _certPem    = null;   /* string */
    var _certSig    = null;   /* Uint8Array – raw sig bytes extracted from cert */
    var _ready      = false;

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
         * Safe to call multiple times; subsequent calls are no-ops.
         */
        init: async function () {
            if (_ready) return;

            var stored = load();

            if (stored && stored.uniqueId && stored.pkcs8Pem && stored.certPem) {
                /* Restore from localStorage */
                try {
                    _id         = stored.uniqueId;
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
            console.log('[Identity] Generating new RSA-2048 identity…');
            var uid = TwilightCrypto.bytesToHex(TwilightCrypto.randomBytes(16));

            var identity = await TwilightCrypto.generateKeyAndCert();

            /* Export private key as PKCS#8 PEM for storage */
            var pkcs8Der = new Uint8Array(
                await window.crypto.subtle.exportKey('pkcs8', identity.privateKey)
            );
            var pkcs8Pem = TwilightCrypto.bytesToPem(pkcs8Der, 'PRIVATE KEY');

            _id         = uid;
            _privateKey = identity.privateKey;
            _certDer    = identity.certDer;
            _certPem    = identity.certPem;
            _certSig    = identity.certSig;
            _ready      = true;

            save(uid, pkcs8Pem, _certPem);
            console.log('[Identity] Generated new identity, uid:', _id);
        },

        /** 32-hex-char unique device ID, sent as &uniqueid= in every request. */
        getUniqueId: function () { return _id; },

        /**
         * Hex-encoded PEM bytes of the client certificate.
         * This is what GameStream expects for the &clientcert= parameter:
         *   hex( UTF-8 bytes of "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n" )
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

        /** True once init() has completed successfully. */
        isReady: function () { return _ready; },

        /**
         * Wipe the stored identity and force re-generation on next init().
         * Call this if pairing state is fully reset.
         */
        reset: function () {
            localStorage.removeItem(STORAGE_KEY);
            _id = _privateKey = _certDer = _certPem = _certSig = null;
            _ready = false;
            console.log('[Identity] Identity wiped');
        },
    };

}());
