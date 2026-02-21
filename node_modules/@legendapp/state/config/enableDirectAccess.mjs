import { configureLegendState, internal } from '@legendapp/state';

function enableDirectAccess() {
    const { observableFns, set } = internal;
    configureLegendState({
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

export { enableDirectAccess };
//# sourceMappingURL=enableDirectAccess.mjs.map
