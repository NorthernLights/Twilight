/*
 * Copyright (C) 2025 Twilight Contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Twilight Sunshine Host Discovery Service
 *
 * Discovers Sunshine (LizardByte/Sunshine) and GameStream hosts on the
 * local network using multicast DNS (mDNS/Zeroconf) and TCP port probing,
 * mirroring the discovery mechanism used by moonlight-tv.
 *
 * mDNS service types queried:
 *   _nvstream._tcp.local  – NVIDIA GameStream / Sunshine compatibility
 *   _sunshine._tcp.local  – Sunshine-native advertisement
 *
 * Luna service ID: com.twilightstream.client.service
 * Methods:
 *   scan       – Discover Sunshine/GameStream hosts on the local network
 *   getVersion – Return the service version string
 */
'use strict';

var pkgInfo = require('./package.json');
var Service = require('webos-service');
var dgram   = require('dgram');
var http    = require('http');
var https   = require('https');
var net     = require('net');
var os      = require('os');

var service = new Service(pkgInfo.name);

// ── Constants ────────────────────────────────────────────────────────────────

var MDNS_MULTICAST_ADDR = '224.0.0.251';
var MDNS_PORT           = 5353;
var GS_HTTP_PORT        = 47989;

/** mDNS service types that Sunshine advertises (and that GameStream used). */
var MDNS_SERVICE_TYPES = [
    '_nvstream._tcp.local',
    '_sunshine._tcp.local',
];

var DEFAULT_SCAN_TIMEOUT = 5000;   // ms – discovery window
var HTTP_VERIFY_TIMEOUT  = 3000;   // ms – per /serverinfo request
var TCP_PROBE_TIMEOUT    = 500;    // ms – per TCP port-open check

// ── DNS Packet Utilities ─────────────────────────────────────────────────────

/**
 * Encode a dot-separated domain name as a sequence of DNS length-prefixed
 * labels, terminated by a zero-length label (root).
 * @param  {string} name  e.g. "_nvstream._tcp.local"
 * @return {number[]}     array of bytes
 */
function encodeDnsName(name) {
    var parts  = [];
    var labels = name.replace(/\.$/, '').split('.');
    labels.forEach(function (label) {
        if (!label.length) return;
        parts.push(label.length & 0xFF);
        for (var i = 0; i < label.length; i++) {
            parts.push(label.charCodeAt(i) & 0xFF);
        }
    });
    parts.push(0); // root label
    return parts;
}

/**
 * Build a minimal mDNS query packet asking for PTR records of serviceType.
 * @param  {string} serviceType  e.g. "_nvstream._tcp.local"
 * @return {Buffer}
 */
function buildMdnsQuery(serviceType) {
    var qname = encodeDnsName(serviceType);
    var buf   = Buffer.alloc(12 + qname.length + 4);

    // DNS Header
    buf.writeUInt16BE(0, 0);   // ID = 0 (required by mDNS)
    buf.writeUInt16BE(0, 2);   // Flags: standard query
    buf.writeUInt16BE(1, 4);   // QDCOUNT: 1 question
    buf.writeUInt16BE(0, 6);   // ANCOUNT: 0
    buf.writeUInt16BE(0, 8);   // NSCOUNT: 0
    buf.writeUInt16BE(0, 10);  // ARCOUNT: 0

    // Question section
    var off = 12;
    qname.forEach(function (b) { buf.writeUInt8(b, off++); });
    buf.writeUInt16BE(12, off);      // QTYPE: PTR (12)
    buf.writeUInt16BE(1,  off + 2);  // QCLASS: IN (1)

    return buf;
}

/**
 * Read a compressed or uncompressed DNS name from buf starting at off.
 * Returns { name: string, next: number } where next is the byte offset
 * immediately after the name field (ignoring pointer targets).
 */
function readDnsName(buf, off) {
    var labels  = [];
    var jumped  = false;
    var end     = off;
    var safety  = 0;

    while (safety++ < 128 && off < buf.length) {
        var len = buf.readUInt8(off);

        if (len === 0) {
            if (!jumped) end = off + 1;
            break;
        }

        // Pointer (DNS name compression)
        if ((len & 0xC0) === 0xC0) {
            if (!jumped) end = off + 2;
            off    = ((len & 0x3F) << 8) | buf.readUInt8(off + 1);
            jumped = true;
            continue;
        }

        off++;
        labels.push(buf.slice(off, off + len).toString('ascii'));
        off += len;
        if (!jumped) end = off;
    }

    return { name: labels.join('.'), next: end };
}

/**
 * Parse a DNS/mDNS response packet and return all IPv4 addresses found
 * in Type-A resource records (from any section: answer, authority, additional).
 * @param  {Buffer}   buf
 * @return {string[]} array of dotted-decimal IPv4 strings
 */
function extractARecordIPs(buf) {
    if (buf.length < 12) return [];

    var qdcount = buf.readUInt16BE(4);
    var ancount = buf.readUInt16BE(6);
    var nscount = buf.readUInt16BE(8);
    var arcount = buf.readUInt16BE(10);
    var total   = ancount + nscount + arcount;
    var off     = 12;

    // Skip question section
    for (var q = 0; q < qdcount; q++) {
        var qr = readDnsName(buf, off);
        off = qr.next + 4; // QTYPE(2) + QCLASS(2)
        if (off > buf.length) return [];
    }

    var ips = [];

    // Parse resource records
    for (var r = 0; r < total; r++) {
        if (off + 11 > buf.length) break;

        var rr    = readDnsName(buf, off);
        off       = rr.next;
        if (off + 10 > buf.length) break;

        var rtype  = buf.readUInt16BE(off);      // TYPE
        // skip CLASS(2) + TTL(4) = 6 bytes, then RDLENGTH(2)
        var rdlen  = buf.readUInt16BE(off + 8);
        var rdata  = off + 10;
        off        = rdata + rdlen;

        // Type A = 1: 4-byte IPv4 address
        if (rtype === 1 && rdlen === 4 && rdata + 4 <= buf.length) {
            ips.push([
                buf.readUInt8(rdata),
                buf.readUInt8(rdata + 1),
                buf.readUInt8(rdata + 2),
                buf.readUInt8(rdata + 3),
            ].join('.'));
        }
    }

    return ips;
}

// ── Host Verification ─────────────────────────────────────────────────────────

/**
 * Hit the GameStream/Sunshine /serverinfo endpoint and parse the response.
 * Calls back with (null, { ip, port, name, paired }) on success, or (Error) on failure.
 *
 * The `once` guard ensures callback is never invoked more than once, preventing
 * the double-call that occurs when req.destroy() (called from the timeout handler)
 * subsequently emits an 'error' event.
 */
function verifyHost(ip, port, callback) {
    var called = false;
    function once(err, info) {
        if (called) return;
        called = true;
        callback(err, info);
    }

    var opts = {
        host:    ip,
        port:    port,
        path:    '/serverinfo',
        method:  'GET',
        timeout: HTTP_VERIFY_TIMEOUT,
    };

    var req = http.request(opts, function (res) {
        var body = '';
        res.on('data', function (d) { body += d; });
        res.on('end',  function () {
            var statusMatch = body.match(/status_code="?(\d+)"?/);
            if (!statusMatch || statusMatch[1] !== '200') {
                return once(new Error('Unexpected status_code'));
            }
            var nameMatch = body.match(/<hostname>([^<]+)<\/hostname>/);
            var pairMatch = body.match(/<PairStatus>(\d)<\/PairStatus>/);
            once(null, {
                ip:     ip,
                port:   port,
                name:   nameMatch ? nameMatch[1] : ip,
                paired: pairMatch ? pairMatch[1] === '1' : false,
            });
        });
    });

    req.on('timeout', function () { req.destroy(); once(new Error('timeout')); });
    req.on('error',   function (e) { once(e); });
    req.end();
}

// ── TCP Port Probe ────────────────────────────────────────────────────────────

/**
 * Attempt a TCP connection to ip:port. Calls back with true if the port is
 * open (connection accepted), false otherwise. Timeout is TCP_PROBE_TIMEOUT.
 */
function tcpPortOpen(ip, port, callback) {
    var socket = new net.Socket();
    var done   = false;

    function finish(open) {
        if (done) return;
        done = true;
        socket.destroy();
        callback(open);
    }

    socket.setTimeout(TCP_PROBE_TIMEOUT);
    socket.on('connect', function () { finish(true);  });
    socket.on('timeout', function () { finish(false); });
    socket.on('error',   function () { finish(false); });
    socket.connect(port, ip);
}

// ── Local Network Utilities ───────────────────────────────────────────────────

/**
 * Return the first three octets of each non-loopback IPv4 interface address,
 * e.g. ["192.168.1", "10.0.0"]. Used to build /24 scan ranges.
 */
function getSubnetPrefixes() {
    var prefixes = [];
    var ifaces   = os.networkInterfaces();
    Object.keys(ifaces).forEach(function (name) {
        (ifaces[name] || []).forEach(function (addr) {
            if (addr.family === 'IPv4' && !addr.internal) {
                prefixes.push(addr.address.split('.').slice(0, 3).join('.'));
            }
        });
    });
    return prefixes;
}

// ── Scan Orchestration ────────────────────────────────────────────────────────

/**
 * Discover Sunshine/GameStream hosts via two parallel mechanisms:
 *   1. mDNS multicast query for _nvstream._tcp.local and _sunshine._tcp.local
 *   2. TCP port probe of every address in the device's /24 subnet(s)
 *
 * After `timeout` ms the discovery window closes and all candidate IPs are
 * verified via HTTP /serverinfo. The verified host list is returned via callback.
 *
 * @param {number}   timeout   Discovery window in milliseconds
 * @param {Function} callback  function(err, hosts[])
 */
function scanForSunshineHosts(timeout, callback) {
    var candidates    = {};      // ip → true  (deduplication set)
    var windowClosed  = false;   // prevents late TCP-probe callbacks adding entries
    var mdnsSockets   = [];

    function addCandidate(ip) {
        if (!windowClosed) candidates[ip] = true;
    }

    // ── 1. mDNS Discovery ──────────────────────────────────────────────────

    MDNS_SERVICE_TYPES.forEach(function (serviceType) {
        var sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        mdnsSockets.push(sock);

        sock.on('message', function (buf) {
            extractARecordIPs(buf).forEach(addCandidate);
        });

        sock.on('error', function (err) {
            console.warn('[Sunshine] mDNS socket error (' + serviceType + '):', err.message);
        });

        sock.bind(0, function () {
            try {
                sock.addMembership(MDNS_MULTICAST_ADDR);
                sock.setMulticastTTL(255);
            } catch (e) {
                console.warn('[Sunshine] Multicast group join warning:', e.message);
            }

            var query = buildMdnsQuery(serviceType);
            sock.send(query, 0, query.length, MDNS_PORT, MDNS_MULTICAST_ADDR, function (err) {
                if (err) {
                    console.warn('[Sunshine] mDNS send error (' + serviceType + '):', err.message);
                } else {
                    console.log('[Sunshine] mDNS query sent for', serviceType);
                }
            });
        });
    });

    // ── 2. TCP Subnet Probe ────────────────────────────────────────────────

    var prefixes = getSubnetPrefixes();
    prefixes.forEach(function (prefix) {
        console.log('[Sunshine] Probing subnet', prefix + '.0/24 on port', GS_HTTP_PORT);
        for (var i = 1; i <= 254; i++) {
            // IIFE to capture loop variable
            (function (ip) {
                tcpPortOpen(ip, GS_HTTP_PORT, function (open) {
                    if (open) {
                        console.log('[Sunshine] Port open at', ip);
                        addCandidate(ip);
                    }
                });
            })(prefix + '.' + i);
        }
    });

    // ── 3. After Discovery Window: Verify All Candidates via HTTP ──────────

    setTimeout(function () {
        windowClosed = true;  // block any late TCP callbacks from adding candidates

        // Stop mDNS sockets
        mdnsSockets.forEach(function (s) {
            try { s.close(); } catch (e) { /* ignore */ }
        });

        var ips = Object.keys(candidates);
        console.log('[Sunshine] Discovery window closed. Candidates:', ips.length, ips);

        if (ips.length === 0) {
            return callback(null, []);
        }

        var results   = [];
        var remaining = ips.length;

        function onVerified(err, info) {
            remaining--;
            if (!err && info) {
                console.log('[Sunshine] Verified host:', info.name, '@', info.ip);
                results.push(info);
            }
            if (remaining === 0) {
                console.log('[Sunshine] Scan complete. Hosts found:', results.length);
                callback(null, results);
            }
        }

        ips.forEach(function (ip) {
            verifyHost(ip, GS_HTTP_PORT, onVerified);
        });

    }, timeout);
}

// ── Luna Service Method Registration ─────────────────────────────────────────

/**
 * scan – Discover Sunshine/GameStream hosts on the local network.
 *
 * Request payload (all optional):
 *   timeout {number}  Discovery window in ms (default: 5000)
 *
 * Response on success:
 *   { returnValue: true, count: N, hosts: [{ ip, port, name, paired }] }
 */
service.register('scan', function (message) {
    var payload = message.payload || {};
    var timeout = (typeof payload.timeout === 'number') ? payload.timeout : DEFAULT_SCAN_TIMEOUT;

    console.log('[Sunshine] scan() called – discovery window:', timeout + 'ms');

    scanForSunshineHosts(timeout, function (err, hosts) {
        if (err) {
            message.respond({
                returnValue: false,
                errorText:   err.message,
                errorCode:   1,
            });
        } else {
            message.respond({
                returnValue: true,
                count:       hosts.length,
                hosts:       hosts,
            });
        }
    });
});

/**
 * pairVerify – Perform the GameStream/Sunshine HTTPS pairing-challenge step.
 *
 * Sunshine uses a self-signed TLS certificate, which Chrome (and therefore
 * the webOS simulator / TV browser) rejects via fetch().  This method proxies
 * the request through Node.js with rejectUnauthorized: false so the self-
 * signed cert is accepted, without compromising the pairing security (the
 * protocol's RSA + AES cryptographic verification already authenticates the
 * server in steps 1–4).
 *
 * Request payload:
 *   ip     {string}  Sunshine host IP address
 *   port   {number}  HTTPS port (default: 47984)
 *   params {object}  Query-string parameters (key/value strings)
 *
 * Response on success: { returnValue: true, xml: "<root>...</root>" }
 * Response on failure: { returnValue: false, errorText: "...", errorCode: N }
 */
service.register('pairVerify', function (message) {
    var payload = message.payload || {};
    var ip      = payload.ip;
    var port    = (typeof payload.port === 'number') ? payload.port : 47984;
    var params  = payload.params || {};

    if (!ip) {
        message.respond({ returnValue: false, errorText: '"ip" is required', errorCode: 1 });
        return;
    }

    /* Build query string */
    var qs = Object.keys(params).map(function (k) {
        return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
    }).join('&');

    var responded = false;
    function reply(obj) {
        if (responded) return;
        responded = true;
        message.respond(obj);
    }

    var options = {
        hostname:           ip,
        port:               port,
        path:               '/pair?' + qs,
        method:             'GET',
        timeout:            12000,
        /* Accept Sunshine's self-signed certificate.
           Security is provided by the RSA/AES handshake in steps 1–4.      */
        rejectUnauthorized: false,
    };

    console.log('[Sunshine] pairVerify →', 'https://' + ip + ':' + port + '/pair?' + qs);

    var req = https.request(options, function (res) {
        var body = '';
        res.on('data', function (chunk) { body += chunk; });
        res.on('end',  function () {
            console.log('[Sunshine] pairVerify ←', body.slice(0, 200));
            reply({ returnValue: true, xml: body });
        });
    });

    req.on('timeout', function () {
        req.destroy();
        reply({ returnValue: false, errorText: 'pairVerify timed out', errorCode: 2 });
    });

    req.on('error', function (e) {
        reply({ returnValue: false, errorText: e.message, errorCode: 3 });
    });

    req.end();
});

/**
 * getVersion – Return the service version as defined in package.json.
 *
 * Response: { returnValue: true, version: "x.y.z" }
 */
service.register('getVersion', function (message) {
    message.respond({
        returnValue: true,
        version:     pkgInfo.version,
    });
});
