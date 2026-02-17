'use strict';

/**
 * Twilight Navigation Engine
 *
 * Spatial D-pad focus management for webOS TV remote control.
 *
 * - Elements with class "focusable" participate in navigation.
 * - Explicit overrides: data-nav-up / data-nav-down / data-nav-left / data-nav-right
 *   contain the data-nav-id of the target element.
 * - Call Navigation.init() once, then Navigation.focusDefault() per screen.
 */
var Navigation = (function () {

    var _focused = null;   // currently focused HTMLElement
    var _zone    = null;   // restrict navigation to this container (modals)

    /* ── Helpers ── */

    function getFocusables() {
        var scope = _zone
            || document.querySelector('.screen.active')
            || document.getElementById('app');
        if (!scope) return [];
        return Array.prototype.slice.call(
            scope.querySelectorAll('.focusable:not([disabled])')
        ).filter(function (el) {
            // Skip elements that are inside a .hidden ancestor
            var p = el;
            while (p && p !== scope) {
                if (p.classList && p.classList.contains('hidden')) return false;
                p = p.parentElement;
            }
            return true;
        });
    }

    function center(el) {
        var r = el.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    }

    /**
     * Spatial nearest-neighbour search.
     * Scores candidates by: primary-axis distance + 2× perpendicular distance.
     * Only considers elements whose center lies strictly in the requested direction.
     */
    function findBest(from, dir) {
        var fc = center(from);
        var candidates = getFocusables();
        var best = null;
        var bestScore = Infinity;

        candidates.forEach(function (el) {
            if (el === from) return;
            var ec = center(el);
            var dx = ec.x - fc.x;
            var dy = ec.y - fc.y;
            var primary, perp;

            switch (dir) {
                case 'up':    if (dy >= -10) return; primary = -dy; perp = Math.abs(dx); break;
                case 'down':  if (dy <=  10) return; primary =  dy; perp = Math.abs(dx); break;
                case 'left':  if (dx >= -10) return; primary = -dx; perp = Math.abs(dy); break;
                case 'right': if (dx <=  10) return; primary =  dx; perp = Math.abs(dy); break;
                default: return;
            }

            var score = primary + perp * 2;
            if (score < bestScore) { bestScore = score; best = el; }
        });
        return best;
    }

    /* ── Focus ── */

    function setFocus(el) {
        if (!el) return;
        if (_focused) {
            _focused.classList.remove('focused');
            _focused.blur();
        }
        _focused = el;
        el.classList.add('focused');
        el.focus({ preventScroll: true });
        // Scroll into view inside scrollable containers
        el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }

    function move(dir) {
        if (!_focused) {
            var first = getFocusables()[0];
            if (first) setFocus(first);
            return;
        }

        // Explicit override via data attribute
        var attrKey = 'nav' + dir.charAt(0).toUpperCase() + dir.slice(1);
        var explicitId = _focused.dataset[attrKey];
        if (explicitId) {
            var target = document.querySelector('[data-nav-id="' + explicitId + '"]');
            if (target && target.classList.contains('focusable')) {
                setFocus(target);
                return;
            }
        }

        var best = findBest(_focused, dir);
        if (best) setFocus(best);
    }

    /* ── Key Handler ── */

    function onKeyDown(e) {
        switch (e.keyCode) {
            case Keys.UP:    e.preventDefault(); move('up');    break;
            case Keys.DOWN:  e.preventDefault(); move('down');  break;
            case Keys.LEFT:  e.preventDefault(); move('left');  break;
            case Keys.RIGHT: e.preventDefault(); move('right'); break;
            case Keys.ENTER:
                e.preventDefault();
                if (_focused) _focused.click();
                break;
            case Keys.BACK:
            case Keys.EXIT:
                e.preventDefault();
                if (typeof App !== 'undefined') App.handleBack();
                break;
            default:
                if (typeof App !== 'undefined') App.handleKey(e.keyCode);
                break;
        }
    }

    /* ── Public API ── */

    return {

        init: function () {
            document.addEventListener('keydown', onKeyDown);
        },

        /** Focus the first focusable element, or a specific one by nav-id. */
        focusDefault: function (navId) {
            if (navId) {
                var el = document.querySelector('[data-nav-id="' + navId + '"]');
                if (el && el.classList.contains('focusable')) { setFocus(el); return; }
            }
            var first = getFocusables()[0];
            if (first) setFocus(first);
        },

        /** Focus a specific element by nav-id. */
        focus: function (navId) {
            var el = document.querySelector('[data-nav-id="' + navId + '"]');
            if (el) setFocus(el);
        },

        /** Focus a DOM element directly. */
        focusEl: function (el) {
            if (el) setFocus(el);
        },

        /** Restrict navigation to a container (e.g., a modal). */
        setZone: function (container) { _zone = container; },

        /** Remove zone restriction. */
        clearZone: function () { _zone = null; },

        /** Current focused element. */
        getCurrent: function () { return _focused; },

        /** Drop focus entirely. */
        clearFocus: function () {
            if (_focused) {
                _focused.classList.remove('focused');
                _focused.blur();
                _focused = null;
            }
        },
    };

}());
