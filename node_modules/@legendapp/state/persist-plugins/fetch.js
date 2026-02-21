'use strict';

var state = require('@legendapp/state');

function persistPluginFetch({ get, set, getInit, setInit, valueType, }) {
    const ret = {
        get() {
            return fetch(get, getInit).then((response) => response[valueType || 'json']());
        },
    };
    if (set) {
        ret.set = async ({ value }) => {
            const requestInfo = state.isString(set) ? { url: set } : set;
            await fetch(Object.assign({ method: 'POST' }, requestInfo, { body: JSON.stringify(value) }), setInit);
            // Return undefined to indicate no changes
        };
    }
    return ret;
}

exports.persistPluginFetch = persistPluginFetch;
//# sourceMappingURL=fetch.js.map
