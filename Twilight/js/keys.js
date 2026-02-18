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
 * webOS TV Remote Control Key Codes
 * @see https://webostv.developer.lge.com/develop/references/webos-tv-system-ui/remote-control
 */
var Keys = Object.freeze({
    UP:           38,
    DOWN:         40,
    LEFT:         37,
    RIGHT:        39,
    ENTER:        13,
    BACK:         461,
    EXIT:         27,    // ESC / also triggers back on some models
    HOME:         36,

    // Media
    PLAY:         415,
    PAUSE:        19,
    PLAY_PAUSE:   179,
    STOP:         413,
    REWIND:       412,
    FAST_FORWARD: 417,

    // Number row
    NUM_0: 48, NUM_1: 49, NUM_2: 50, NUM_3: 51, NUM_4: 52,
    NUM_5: 53, NUM_6: 54, NUM_7: 55, NUM_8: 56, NUM_9: 57,

    // CEC color buttons
    RED:    403,
    GREEN:  404,
    YELLOW: 405,
    BLUE:   406,

    // Info / Guide
    INFO:  457,
    GUIDE: 458,
});
