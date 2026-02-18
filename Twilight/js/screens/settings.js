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
 * Settings Screen
 *
 * Left panel: category navigation (Video / Audio / Input / About).
 * Right panel: settings items rendered from a declarative schema.
 * OK/Enter on a setting cycles through its options.
 */
var Settings = (function () {

    var _category = 'video';
    var _settings = null;

    /* ── Schema ── */

    var SCHEMA = {
        video: {
            label: 'Video',
            sections: [
                {
                    header: 'Quality',
                    items: [
                        { key: 'resolution', name: 'Resolution',    desc: 'Maximum stream resolution',              type: 'select', options: ['720p','1080p','4K'] },
                        { key: 'frameRate',  name: 'Frame Rate',    desc: 'Target frames per second',              type: 'select', options: [30,60,120], fmt: function(v){ return v + ' fps'; } },
                        { key: 'bitrate',    name: 'Video Bitrate', desc: 'Network bandwidth for video',           type: 'range',  min: 5, max: 150, step: 5, fmt: function(v){ return v + ' Mbps'; } },
                        { key: 'codec',      name: 'Codec',         desc: 'H.264 for Compatibility, HEVC for Efficiency, and AV1 for Modern Hosts',  type: 'select', options: ['h264','hevc','av1'], labels: ['H.264','HEVC / H.265','AV1'] },
                    ],
                },
                {
                    header: 'HDR',
                    items: [
                        { key: 'hdr', name: 'HDR', desc: 'High Dynamic Range (requires compatible display and game)', type: 'toggle' },
                    ],
                },
            ],
        },
        audio: {
            label: 'Audio',
            sections: [
                {
                    header: 'Configuration',
                    items: [
                        { key: 'audioConfig',  name: 'Channels',       desc: 'Speaker layout',    type: 'select', options: ['stereo','5.1','7.1'], labels: ['Stereo (2.0)','5.1 Surround','7.1 Surround'] },
                        { key: 'audioBitrate', name: 'Audio Bitrate',  desc: 'Audio quality',     type: 'select', options: [96,192,320], fmt: function(v){ return v + ' kbps'; } },
                    ],
                },
            ],
        },
        input: {
            label: 'Input',
            sections: [
                {
                    header: 'Controller',
                    items: [
                        { key: 'rumble',         name: 'Rumble',            desc: 'Enable controller vibration',    type: 'toggle' },
                        { key: 'mouseEmulation', name: 'Mouse Emulation',   desc: 'Emulate mouse pointer via D-pad', type: 'toggle' },
                    ],
                },
            ],
        },
        about: {
            label: 'About',
            sections: [
                {
                    header: 'Twilight',
                    items: [
                        { key: '_ver',   name: 'Version',          type: 'info', value: '1.0.0' },
                        { key: '_build', name: 'Build',            type: 'info', value: (typeof TwilightBuild !== 'undefined' ? TwilightBuild : '\u2014') },
                        { key: '_svc',   name: 'Twilight Services', type: 'info', value: '\u2014' },
                        { key: '_prot', name: 'Protocol',          type: 'info', value: 'Moonlight (GameStream / Sunshine)' },
                        { key: '_sdk',  name: 'webOS SDK', type: 'info', value: 'webOSTVjs 1.2.10' },
                        { key: '_lic',  name: 'License',   type: 'info', value: 'GNU GPL v3' },
                    ],
                },
                {
                    header: 'Device',
                    items: [
                        { key: '_model', name: 'TV Model',      type: 'info', value: '—' },
                        { key: '_wos',   name: 'webOS',         type: 'info', value: '—' },
                        { key: '_vdec',  name: 'Video Decoder', type: 'info', value: '—' },
                        { key: '_abk',   name: 'Audio Backend', type: 'info', value: '—' },
                    ],
                },
            ],
        },
    };

    /* ── Rendering ── */

    function displayValue(item, val) {
        if (item.type === 'info')   return item.value || '—';
        if (item.type === 'toggle') return val ? 'On' : 'Off';
        if (item.fmt)               return item.fmt(val);
        if (item.labels) {
            var idx = item.options.indexOf(val);
            return idx >= 0 ? item.labels[idx] : String(val);
        }
        return String(val);
    }

    function renderPanel(catId) {
        _category = catId;
        _settings = Storage.getSettings();

        // Update active nav button
        document.querySelectorAll('.settings-nav-btn').forEach(function (btn) {
            btn.classList.toggle('active', btn.dataset.category === catId);
        });

        var cat = SCHEMA[catId];
        if (!cat) return;

        var panel = document.getElementById('settings-panel');
        if (!panel) return;
        var html = '';

        cat.sections.forEach(function (section) {
            html += '<div class="settings-group-header">' + section.header + '</div>';
            section.items.forEach(function (item) {
                var val     = item.type === 'info' ? item.value : _settings[item.key];
                var disp    = displayValue(item, val);
                var isInfo  = item.type === 'info';
                var rowClass = isInfo ? 'setting-row' : 'setting-row focusable';
                html +=
                    '<div class="' + rowClass + '"' +
                    (isInfo ? '' : ' data-nav-id="s-' + item.key + '" data-key="' + item.key + '" tabindex="0"') + '>' +
                        '<div class="setting-info">' +
                            '<div class="setting-name">' + item.name + '</div>' +
                            (item.desc ? '<div class="setting-desc">' + item.desc + '</div>' : '') +
                        '</div>' +
                        '<div class="setting-value" style="' + (isInfo ? 'color:var(--color-text-sub)' : '') + '">' +
                            disp + (isInfo ? '' : '<span class="chevron">&#10095;</span>') +
                        '</div>' +
                    '</div>';
            });
        });

        panel.innerHTML = html;

        var first = panel.querySelector('.focusable');
        if (first && first.dataset.navId) Navigation.focus(first.dataset.navId);
    }

    /* ── Setting mutation ── */

    function allItems() {
        var out = [];
        Object.keys(SCHEMA).forEach(function (catId) {
            SCHEMA[catId].sections.forEach(function (s) {
                s.items.forEach(function (item) { out.push(item); });
            });
        });
        return out;
    }

    function cycleSetting(key) {
        var item = allItems().filter(function (i) { return i.key === key; })[0];
        if (!item || item.type === 'info') return;

        var cur = _settings[key];
        var next;

        if (item.type === 'toggle') {
            next = !cur;
        } else if (item.type === 'select') {
            var idx = item.options.indexOf(cur);
            next = item.options[(idx + 1) % item.options.length];
        } else if (item.type === 'range') {
            var stepped = (cur || item.min) + item.step;
            next = stepped > item.max ? item.min : stepped;
        }

        Storage.updateSettings({ [key]: next });
        renderPanel(_category);
    }

    /* ── Helpers ── */

    function updateAboutItem(key, value) {
        SCHEMA.about.sections.forEach(function (section) {
            section.items.forEach(function (item) {
                if (item.key === key) item.value = value;
            });
        });
    }

    /* ── Device info ── */

    function detectDevice() {
        if (typeof webOS === 'undefined') return;
        webOS.deviceInfo(function (info) {
            if (info.modelName) updateAboutItem('_model', info.modelName);
            if (info.version)   updateAboutItem('_wos',   'webOS ' + (info.version.major || ''));
            if (_category === 'about') renderPanel('about');
        });
    }

    /** Detect supported video codecs via the MediaCapabilities API (Chrome 67+). */
    function detectVideoDecoder() {
        if (!navigator.mediaCapabilities || !navigator.mediaCapabilities.decodingInfo) {
            updateAboutItem('_vdec', '—');
            return;
        }
        var toTest = [
            { label: 'AV1',   contentType: 'video/mp4; codecs="av01.0.08M.08"' },
            { label: 'HEVC',  contentType: 'video/mp4; codecs="hvc1.1.6.L150.90"' },
            { label: 'H.264', contentType: 'video/mp4; codecs="avc1.640028"' },
        ];
        var chain = Promise.resolve([]);
        toTest.forEach(function (codec) {
            chain = chain.then(function (acc) {
                return navigator.mediaCapabilities.decodingInfo({
                    type: 'media-source',
                    video: { contentType: codec.contentType, width: 1920, height: 1080, bitrate: 20000000, framerate: 60 },
                }).then(function (r) {
                    if (r.supported) acc.push(codec.label);
                    return acc;
                }, function () { return acc; });
            });
        });
        chain.then(function (supported) {
            updateAboutItem('_vdec', supported.length > 0 ? supported.join(' / ') : '—');
            if (_category === 'about') renderPanel('about');
        }).catch(function () {
            updateAboutItem('_vdec', '—');
        });
    }

    /** Detect audio output via the webOS Luna audio service. */
    function detectAudioBackend() {
        if (typeof webOS === 'undefined') return;
        var OUTPUT_LABELS = {
            tv_speaker:       'Built-in Speakers',
            external_arc:     'HDMI ARC',
            external_optical: 'Optical',
            bt_soundbar:      'Bluetooth',
            wired_headphone:  'Headphones',
        };
        function applyOutput(soundOutput) {
            var label = OUTPUT_LABELS[soundOutput] || soundOutput || 'LG Audio Engine';
            updateAboutItem('_abk', label);
            if (_category === 'about') renderPanel('about');
        }
        webOS.service.request('luna://com.webos.service.audio', {
            method: 'getStatus',
            parameters: { subscribe: false },
            onSuccess: function (res) {
                applyOutput(res.volumeStatus && res.volumeStatus.soundOutput);
            },
            onFailure: function () {
                webOS.service.request('luna://com.webos.service.sound', {
                    method: 'getSoundOutput',
                    parameters: {},
                    onSuccess: function (res2) { applyOutput(res2.soundOutput); },
                    onFailure: function () {
                        updateAboutItem('_abk', 'LG Audio Engine');
                        if (_category === 'about') renderPanel('about');
                    },
                });
            },
        });
    }

    /** Query the Twilight service for its version and update the About panel. */
    function detectTwilightServices() {
        if (typeof webOS === 'undefined') return;
        webOS.service.request('luna://com.twilightstream.client.service', {
            method: 'getVersion',
            parameters: {},
            onSuccess: function (result) {
                if (!result.version) return;
                updateAboutItem('_svc', result.version);
                if (_category === 'about') renderPanel('about');
            },
            onFailure: function (err) {
                console.error('[Settings] TwilightServices unavailable:', err && err.errorText);
                updateAboutItem('_svc', 'Unavailable');
                if (_category === 'about') renderPanel('about');
            },
        });
    }

    /* ── Public ── */

    return {

        init: function () {
            var nav = document.getElementById('settings-nav');
            if (nav) {
                nav.addEventListener('click', function (e) {
                    var btn = e.target.closest('.settings-nav-btn');
                    if (!btn || !btn.dataset.category) return;
                    renderPanel(btn.dataset.category);
                    /* Re-query the service version each time About is opened
                       so it always reflects the current TwilightServices build. */
                    if (btn.dataset.category === 'about') detectTwilightServices();
                });
            }

            var screen = document.getElementById('screen-settings');
            if (screen) {
                screen.addEventListener('click', function (e) {
                    var row = e.target.closest('.setting-row.focusable');
                    if (row && row.dataset.key) cycleSetting(row.dataset.key);
                });
            }
        },

        onEnter: function () {
            renderPanel('video');
            detectDevice();
            detectVideoDecoder();
            detectAudioBackend();
            detectTwilightServices();
        },

        onLeave: function () {
            _category = 'video';
        },
    };

}());
