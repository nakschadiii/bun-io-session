import { configureLegendState, isObject, tracking, internal } from '@legendapp/state';
import { useSelector } from '@legendapp/state/react';
import { createContext, __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED, useContext } from 'react';

const ReactRenderContext = createContext(0);
function needsSelector() {
    // If we're already tracking then we definitely don't need useSelector
    if (!tracking.current) {
        try {
            // If there's no dispatcher we're definitely not in React
            // This is an optimization to not need to run useContext. If in a future React version
            // this works differently we can change it or just remove it.
            const dispatcher = __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentDispatcher.current;
            if (dispatcher) {
                // If there's a dispatcher then we may be inside of a hook.
                // Attempt a useContext hook, which will throw an error if outside of render.
                useContext(ReactRenderContext);
                return true;
            }
        }
        catch (_a) { } // eslint-disable-line no-empty
    }
    return false;
}
function enableReactTracking({ auto, warnUnobserved }) {
    const { get } = internal;
    configureLegendState({
        observableFunctions: {
            get: (node, options) => {
                if (needsSelector()) {
                    if (auto) {
                        return useSelector(() => get(node, options), isObject(options) ? options : undefined);
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

export { enableReactTracking };
//# sourceMappingURL=enableReactTracking.mjs.map
