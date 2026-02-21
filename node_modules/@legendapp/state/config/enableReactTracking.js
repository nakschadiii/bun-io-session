'use strict';

var state = require('@legendapp/state');
var react$1 = require('@legendapp/state/react');
var react = require('react');

const ReactRenderContext = react.createContext(0);
function needsSelector() {
    // If we're already tracking then we definitely don't need useSelector
    if (!state.tracking.current) {
        try {
            // If there's no dispatcher we're definitely not in React
            // This is an optimization to not need to run useContext. If in a future React version
            // this works differently we can change it or just remove it.
            const dispatcher = react.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentDispatcher.current;
            if (dispatcher) {
                // If there's a dispatcher then we may be inside of a hook.
                // Attempt a useContext hook, which will throw an error if outside of render.
                react.useContext(ReactRenderContext);
                return true;
            }
        }
        catch (_a) { } // eslint-disable-line no-empty
    }
    return false;
}
function enableReactTracking({ auto, warnUnobserved }) {
    const { get } = state.internal;
    state.configureLegendState({
        observableFunctions: {
            get: (node, options) => {
                if (needsSelector()) {
                    if (auto) {
                        return react$1.useSelector(() => get(node, options), state.isObject(options) ? options : undefined);
                    }
                    else if (process.env.NODE_ENV === 'development' && warnUnobserved) {
                        console.warn('[legend-state] Detected a `get()` call in an unobserved component. You may want to wrap it in observer: https://legendapp.com/open-source/state/react-api/#observer-hoc');
                    }
                }
                return get(node, options);
            },
        },
    });
}

exports.enableReactTracking = enableReactTracking;
//# sourceMappingURL=enableReactTracking.js.map
