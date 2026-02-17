'use strict';

/**
 * Twilight Storage Service
 * Wraps localStorage for host list and settings persistence.
 * webOS supports up to ~5MB of localStorage per app.
 */
var Storage = (function () {

    var HOSTS_KEY    = 'twilight.hosts';
    var SETTINGS_KEY = 'twilight.settings';

    var DEFAULTS = {
        // Video
        resolution: '1080p',   // '720p' | '1080p' | '4K'
        frameRate:  60,         // 30 | 60 | 120
        bitrate:    20,         // Mbps
        codec:      'hevc',     // 'h264' | 'hevc' | 'av1'
        hdr:        false,
        // Audio
        audioConfig:  'stereo', // 'stereo' | '5.1' | '7.1'
        audioBitrate: 192,      // kbps
        // Input
        rumble:         true,
        mouseEmulation: false,
    };

    function read(key, fallback) {
        try {
            var raw = localStorage.getItem(key);
            return raw !== null ? JSON.parse(raw) : fallback;
        } catch (e) {
            console.warn('[Storage] read error', key, e);
            return fallback;
        }
    }

    function write(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch (e) {
            console.warn('[Storage] write error', key, e);
        }
    }

    return {

        /* ── Host Management ── */

        getHosts: function () {
            return read(HOSTS_KEY, []);
        },

        getHost: function (id) {
            return this.getHosts().find(function (h) { return h.id === id; }) || null;
        },

        saveHost: function (host) {
            var hosts = this.getHosts();
            var idx   = hosts.findIndex(function (h) { return h.id === host.id; });
            if (idx >= 0) {
                hosts[idx] = Object.assign({}, hosts[idx], host);
            } else {
                hosts.push(host);
            }
            write(HOSTS_KEY, hosts);
        },

        removeHost: function (id) {
            write(HOSTS_KEY, this.getHosts().filter(function (h) { return h.id !== id; }));
        },

        /** Create a blank host object with a unique ID. */
        createHost: function (ip, displayName) {
            return {
                id:         'h' + Date.now() + Math.random().toString(36).slice(2, 6),
                ip:         ip.trim(),
                name:       displayName.trim() || ip.trim(),
                status:     'unknown',  // 'online' | 'offline' | 'pairing' | 'unknown'
                paired:     false,
                serverInfo: null,
                addedAt:    Date.now(),
            };
        },

        /* ── Settings ── */

        getSettings: function () {
            return Object.assign({}, DEFAULTS, read(SETTINGS_KEY, {}));
        },

        updateSettings: function (patch) {
            write(SETTINGS_KEY, Object.assign(this.getSettings(), patch));
        },

        resetSettings: function () {
            write(SETTINGS_KEY, {});
        },

        getDefaults: function () {
            return Object.assign({}, DEFAULTS);
        },
    };

}());
