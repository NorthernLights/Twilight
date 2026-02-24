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
 * TwilightCrypto – WebCrypto primitives for the GameStream pairing protocol.
 *
 * Protocol uses (per nvpairingmanager.cpp reference):
 *   • AES-128-ECB  – no padding, blocks are multiples of 16 bytes
 *   • SHA-256      – key derivation and challenge hashing
 *   • RSA-2048 PKCS#1 v1.5 / SHA-256 – signing & verification
 *   • Minimal X.509 DER – self-signed client certificate
 *
 * WebCrypto does not expose AES-ECB.  We simulate it per-block with
 * AES-CBC(IV = 0), exploiting the fact that for a single 16-byte block
 * CBC(IV=0) ≡ ECB.  Multi-block decrypt uses the correction formula:
 *   ECB_P[0]  = CBC_P[0]                (IV = 0 ⟹ no XOR on first block)
 *   ECB_P[i]  = CBC_P[i] XOR C[i-1]    for i > 0
 *
 * webOS 5 / Chrome 79+ compatibility: no optional-chaining, no nullish
 * coalescing, no top-level await.  ES6 (arrow fns, Promises, async/await,
 * destructuring) is fully supported.
 */
var TwilightCrypto = (function () {

    var subtle = window.crypto.subtle;

    /* ─────────────────────────────────────────────
       Binary helpers
       ───────────────────────────────────────────── */

    function concat() {
        var arrays = Array.from(arguments);
        var len = arrays.reduce(function (n, a) { return n + a.length; }, 0);
        var out = new Uint8Array(len);
        var off = 0;
        arrays.forEach(function (a) { out.set(a, off); off += a.length; });
        return out;
    }

    function hexToBytes(hex) {
        if (hex.length % 2 !== 0) throw new Error('Odd-length hex string');
        var b = new Uint8Array(hex.length >>> 1);
        for (var i = 0; i < b.length; i++) {
            b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    function bytesToHex(bytes) {
        return Array.from(bytes).map(function (b) {
            return ('0' + (b & 0xff).toString(16)).slice(-2);
        }).join('');
    }

    function randomBytes(n) {
        return window.crypto.getRandomValues(new Uint8Array(n));
    }

    function xorBytes(a, b) {
        var out = new Uint8Array(a.length);
        for (var i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
        return out;
    }

    function pemToBytes(pem) {
        var b64 = pem.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, '');
        var raw = atob(b64);
        var bytes = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
        return bytes;
    }

    function bytesToPem(der, label) {
        var b64 = btoa(String.fromCharCode.apply(null, der));
        var lines = '-----BEGIN ' + label + '-----\n';
        for (var i = 0; i < b64.length; i += 64) lines += b64.slice(i, i + 64) + '\n';
        lines += '-----END ' + label + '-----\n';
        return lines;
    }

    /* ─────────────────────────────────────────────
       Minimal DER / ASN.1 encoder
       ───────────────────────────────────────────── */

    var DER = (function () {
        function encLen(n) {
            if (n < 0x80)      return [n];
            if (n < 0x100)     return [0x81, n];
            if (n < 0x10000)   return [0x82, (n >> 8) & 0xff, n & 0xff];
            throw new Error('DER length > 65535 not supported');
        }

        function tlv(tag, body) {
            var b = Array.from(body instanceof Uint8Array ? body : new Uint8Array(body));
            return new Uint8Array([tag].concat(encLen(b.length)).concat(b));
        }

        function seq(items)    { return tlv(0x30, concat.apply(null, items)); }
        function setOf(items)  { return tlv(0x31, concat.apply(null, items)); }
        function bitStr(bytes) { return tlv(0x03, concat(new Uint8Array([0x00]), bytes)); }
        function nullVal()     { return new Uint8Array([0x05, 0x00]); }
        function ctx0(items)   { return tlv(0xa0, concat.apply(null, items)); }

        function integer(raw) {
            /* Strip unnecessary leading 0x00 bytes (canonical DER INTEGER).
             * OpenSSL's i2d_X509 re-encodes using minimal form, so any cert we
             * send with a non-canonical serial causes an X509_cmp mismatch in
             * Sunshine's pairchallenge verify callback. */
            var start = 0;
            while (start < raw.length - 1 && raw[start] === 0x00 && (raw[start + 1] & 0x80) === 0) {
                start++;
            }
            if (start > 0) raw = raw.slice(start);
            /* Ensure positive (prepend 0x00 if high bit set) */
            var data = (raw[0] & 0x80) ? concat(new Uint8Array([0x00]), raw) : raw;
            return tlv(0x02, data);
        }

        function intSmall(n) {
            /* Encode a small non-negative integer (≤ 32767) */
            if (n < 0x80)   return tlv(0x02, new Uint8Array([n]));
            if (n < 0x8000) return tlv(0x02, new Uint8Array([0x00, (n >> 8) & 0xff, n & 0xff]));
            throw new Error('intSmall: value too large');
        }

        function oid(dotStr) {
            var arcs = dotStr.split('.').map(Number);
            var bytes = [arcs[0] * 40 + arcs[1]];
            for (var i = 2; i < arcs.length; i++) {
                var v = arcs[i], tmp = [];
                tmp.push(v & 0x7f);
                v >>= 7;
                while (v > 0) { tmp.push((v & 0x7f) | 0x80); v >>= 7; }
                tmp.reverse().forEach(function (b) { bytes.push(b); });
            }
            return tlv(0x06, new Uint8Array(bytes));
        }

        function utf8Str(s)       { return tlv(0x0c, new TextEncoder().encode(s)); }
        function printableStr(s)  { return tlv(0x13, new TextEncoder().encode(s)); }

        function utcTime(d) {
            var p = function (n) { return (n < 10 ? '0' : '') + n; };
            var s = p(d.getUTCFullYear() % 100) + p(d.getUTCMonth() + 1) +
                    p(d.getUTCDate()) + p(d.getUTCHours()) +
                    p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + 'Z';
            return tlv(0x17, new TextEncoder().encode(s));
        }

        /* AlgorithmIdentifier { OID, NULL } */
        var SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
        var RSA_ENCRYPTION  = '1.2.840.113549.1.1.1';

        function algId(oidStr) { return seq([oid(oidStr), nullVal()]); }

        /* Distinguished Name: SEQUENCE { SET { SEQUENCE { OID(CN), PrintableString } } }
         * Use PrintableString (0x13) to match OpenSSL MBSTRING_ASC encoding.
         * Sunshine's X509_cmp compares raw DER bytes; UTF8String (0x0C) vs
         * PrintableString (0x13) would cause a silent mismatch and unpersisted pairing. */
        function rdnCn(cn) {
            return seq([setOf([seq([oid('2.5.4.3'), printableStr(cn)])])]);
        }

        return {
            seq: seq, setOf: setOf, bitStr: bitStr, nullVal: nullVal,
            ctx0: ctx0, integer: integer, intSmall: intSmall, oid: oid,
            utf8Str: utf8Str, printableStr: printableStr, utcTime: utcTime,
            algId: algId, rdnCn: rdnCn,
            SHA256_WITH_RSA: SHA256_WITH_RSA,
            RSA_ENCRYPTION: RSA_ENCRYPTION,
        };
    }());

    /* ─────────────────────────────────────────────
       Minimal DER / X.509 parser
       ───────────────────────────────────────────── */

    function readLen(data, off) {
        var b = data[off++];
        if (b < 0x80) return { len: b, off: off };
        var nb = b & 0x7f, len = 0;
        for (var i = 0; i < nb; i++) len = (len << 8) | data[off++];
        return { len: len, off: off };
    }

    function readTlv(data, off) {
        var tag = data[off++];
        var l = readLen(data, off);
        return { tag: tag, value: data.slice(l.off, l.off + l.len), end: l.off + l.len };
    }

    /**
     * Extract the raw RSA signature bytes from a DER-encoded X.509 certificate.
     * (Equivalent to OpenSSL's X509_get0_signature → asnSignature->data)
     */
    function parseCertSignature(certDer) {
        var outer = readTlv(certDer, 0).value;
        var off = 0;
        var tbs = readTlv(outer, off);   off = tbs.end;   // skip TBSCertificate
        var alg = readTlv(outer, off);   off = alg.end;   // skip AlgorithmIdentifier
        var sig = readTlv(outer, off);                    // BIT STRING
        return sig.value.slice(1);  /* strip unused-bits prefix byte (0x00) */
    }

    /**
     * Extract the SubjectPublicKeyInfo (SPKI) DER bytes from a cert.
     * Needed to import the server's public key for signature verification.
     */
    function extractSpkiFromCert(certDer) {
        var tbs = readTlv(readTlv(certDer, 0).value, 0).value;
        var off = 0;
        /* Skip optional [0] version */
        if (tbs[off] === 0xa0) { off = readTlv(tbs, off).end; }
        off = readTlv(tbs, off).end;  /* serialNumber */
        off = readTlv(tbs, off).end;  /* signature AlgId */
        off = readTlv(tbs, off).end;  /* issuer */
        off = readTlv(tbs, off).end;  /* validity */
        off = readTlv(tbs, off).end;  /* subject */
        var spki = readTlv(tbs, off);
        return tbs.slice(off, spki.end);  /* raw DER of SPKI */
    }

    /* ─────────────────────────────────────────────
       AES-128-ECB (simulated via per-block CBC)
       ───────────────────────────────────────────── */

    var ZERO_IV = new Uint8Array(16);

    async function importAesCbcKey(keyBytes) {
        return subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
    }

    /**
     * AES-128-ECB encrypt – no PKCS#7 padding.
     * plaintext.length must be a multiple of 16.
     */
    async function aesEcbEncrypt(keyBytes, plaintext) {
        if (plaintext.length % 16 !== 0) throw new Error('ECB encrypt: length must be multiple of 16');
        var key = await importAesCbcKey(keyBytes);
        var result = new Uint8Array(plaintext.length);
        for (var i = 0; i < plaintext.length; i += 16) {
            var block = plaintext.slice(i, i + 16);
            /* AES-CBC-encrypt of exactly one block with IV=0:
               cipher = AES_encrypt(block XOR 0) = AES_encrypt(block) = ECB(block)
               WebCrypto appends a PKCS#7 padding block → output is 32 bytes;
               we keep only the first 16 bytes (the actual ciphertext block). */
            var enc = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: ZERO_IV }, key, block));
            result.set(enc.slice(0, 16), i);
        }
        return result;
    }

    /**
     * AES-128-ECB decrypt – no PKCS#7 padding.
     * ciphertext.length must be a multiple of 16.
     *
     * We cannot simply use AES-CBC-decrypt per-block because WebCrypto always
     * strips PKCS#7 padding from the last block, yielding unpredictable lengths.
     *
     * Solution: append a crafted padding block whose CBC-decryption yields
     * exactly [0x10 × 16] (valid PKCS#7), let WebCrypto strip it, then
     * un-XOR the previous ciphertext blocks from the CBC plaintext to recover
     * the true ECB plaintext.
     */
    async function aesEcbDecrypt(keyBytes, ciphertext) {
        if (ciphertext.length % 16 !== 0) throw new Error('ECB decrypt: length must be multiple of 16');
        var key = await importAesCbcKey(keyBytes);

        /* Build the padding-sentinel block:
           We want AES_decrypt(padBlock) XOR C[N-1] = [0x10]*16
           ⟹ padBlock = AES_encrypt([0x10]*16 XOR C[N-1])              */
        var lastBlock = ciphertext.slice(ciphertext.length - 16);
        var pad16 = new Uint8Array(16).fill(0x10);
        var padInput = xorBytes(pad16, lastBlock);
        var padBlock = await aesEcbEncrypt(keyBytes, padInput);  /* single-block encrypt */

        /* Decrypt [ciphertext || padBlock] with AES-CBC, IV=0.
           The padding sentinel decrypts to valid 0x10×16 PKCS#7 → stripped.
           Output length = ciphertext.length (original N blocks).            */
        var toDecrypt = concat(ciphertext, padBlock);
        var decrypted = new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv: ZERO_IV }, key, toDecrypt));

        /* Correct CBC-vs-ECB difference:
           ECB_P[0] = CBC_P[0]              (IV = 0, so no correction needed)
           ECB_P[i] = CBC_P[i] XOR C[i-1]  for i > 0                        */
        var n = ciphertext.length / 16;
        var result = new Uint8Array(ciphertext.length);
        result.set(decrypted.slice(0, 16), 0);
        for (var i = 1; i < n; i++) {
            var cbcSlice = decrypted.slice(i * 16, (i + 1) * 16);
            var prevC    = ciphertext.slice((i - 1) * 16, i * 16);
            result.set(xorBytes(cbcSlice, prevC), i * 16);
        }
        return result;
    }

    /* ─────────────────────────────────────────────
       SHA-256
       ───────────────────────────────────────────── */

    async function sha256(data) {
        return new Uint8Array(await subtle.digest('SHA-256', data));
    }

    /* ─────────────────────────────────────────────
       RSA-2048 PKCS#1 v1.5 / SHA-256
       ───────────────────────────────────────────── */

    /** Sign data with the client's RSA private key. */
    async function rsaSign(data, privateKey) {
        return new Uint8Array(await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, privateKey, data));
    }

    /**
     * Verify a signature produced by the server certificate's private key.
     * serverCertDer – Uint8Array of the server's DER certificate.
     */
    async function rsaVerify(data, signature, serverCertDer) {
        var spkiBytes = extractSpkiFromCert(serverCertDer);
        var pubKey = await subtle.importKey(
            'spki', spkiBytes,
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            false, ['verify']
        );
        return subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, pubKey, signature, data);
    }

    /* ─────────────────────────────────────────────
       Self-signed X.509 certificate generation
       ───────────────────────────────────────────── */

    /**
     * Generate an RSA-2048 key pair and a minimal self-signed X.509 certificate.
     *
     * Returns:
     *   { privateKey  – CryptoKey (RSASSA-PKCS1-v1_5 / SHA-256)
     *     publicKey   – CryptoKey
     *     certDer     – Uint8Array  (full certificate in DER)
     *     certPem     – string      (PEM-encoded certificate)
     *     certSig     – Uint8Array  (raw RSA signature bytes extracted from cert,
     *                                equivalent to OpenSSL X509_get0_signature) }
     */
    async function generateKeyAndCert() {
        /* 1. Generate RSA-2048 key pair */
        var kp = await subtle.generateKey(
            { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
              publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
              hash: 'SHA-256' },
            true,   /* extractable – needed to export for storage */
            ['sign', 'verify']
        );

        /* 2. Export SPKI (the SubjectPublicKeyInfo DER, used directly in the cert) */
        var spki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));

        /* 3. Build TBSCertificate */
        var serial = randomBytes(16);
        serial[0] &= 0x7f;          /* ensure positive */
        if (serial[0] === 0x00) serial[0] = 0x01;  /* prevent leading zero in DER integer */

        var now    = new Date();
        var expiry = new Date(Date.UTC(now.getUTCFullYear() + 20,
                                       now.getUTCMonth(),
                                       now.getUTCDate()));

        var tbs = DER.seq([
            DER.ctx0([DER.intSmall(2)]),                    /* version: v3        */
            DER.integer(serial),                             /* serialNumber       */
            DER.algId(DER.SHA256_WITH_RSA),                  /* signature AlgId    */
            DER.rdnCn('NVIDIA GameStream Client'),           /* issuer             */
            DER.seq([DER.utcTime(now), DER.utcTime(expiry)]),/* validity           */
            DER.rdnCn('NVIDIA GameStream Client'),           /* subject            */
            spki,                                            /* subjectPublicKeyInfo*/
        ]);

        /* 4. Sign TBSCertificate with private key */
        var sig = await rsaSign(tbs, kp.privateKey);

        /* 5. Assemble full Certificate */
        var certDer = DER.seq([
            tbs,
            DER.algId(DER.SHA256_WITH_RSA),
            DER.bitStr(sig),
        ]);

        return {
            privateKey: kp.privateKey,
            publicKey:  kp.publicKey,
            certDer:    certDer,
            certPem:    bytesToPem(certDer, 'CERTIFICATE'),
            certSig:    sig,   /* same bytes OpenSSL's X509_get0_signature returns */
        };
    }

    /* ─────────────────────────────────────────────
       Public API
       ───────────────────────────────────────────── */

    return {
        randomBytes:          randomBytes,
        hexToBytes:           hexToBytes,
        bytesToHex:           bytesToHex,
        pemToBytes:           pemToBytes,
        bytesToPem:           bytesToPem,
        sha256:               sha256,
        aesEcbEncrypt:        aesEcbEncrypt,
        aesEcbDecrypt:        aesEcbDecrypt,
        rsaSign:              rsaSign,
        rsaVerify:            rsaVerify,
        parseCertSignature:   parseCertSignature,
        extractSpkiFromCert:  extractSpkiFromCert,
        generateKeyAndCert:   generateKeyAndCert,
    };

}());
