'use strict';

var state = require('@legendapp/state');

function enableDirectAccess() {
    const { observableFns, set } = state.internal;
    state.configureLegendState({
        observableProperties: {
            $: {
                get(node) {
                    // Get it from the observableFns Map because another config function
                    // might have overriden get
                    const get = observableFns.get('get');
                    return get(node);
                },
                set(node, value) {
                    return set(node, value);
                },
            },
        },
    });
}

exports.enableDirectAccess = enableDirectAccess;
//# sourceMappingURL=enableDirectAccess.js.map
