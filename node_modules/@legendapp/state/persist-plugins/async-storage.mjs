import { isArray, setAtPath, internal } from '@legendapp/state';

const MetadataSuffix = '__m';
let AsyncStorage;
const { safeParse, safeStringify } = internal;
class ObservablePersistAsyncStorage {
    constructor() {
        this.data = {};
    }
    // Init
    async initialize(config) {
        let tables = [];
        const storageConfig = config.asyncStorage;
        if (storageConfig) {
            AsyncStorage = storageConfig.AsyncStorage;
            const { preload } = storageConfig;
            try {
                if (preload === true) {
                    // If preloadAllKeys, load all keys and preload tables on startup
                    tables = await AsyncStorage.getAllKeys();
                }
                else if (isArray(preload)) {
                    // If preloadKeys, preload load the tables on startup
                    tables = preload;
                }
                if (tables) {
                    const values = await AsyncStorage.multiGet(tables);
                    values.forEach(([table, value]) => {
                        this.data[table] = value ? safeParse(value) : undefined;
                    });
                }
            }
            catch (e) {
                console.error('[legend-state] ObservablePersistAsyncStorage failed to initialize', e);
            }
        }
        else {
            console.error('[legend-state] Missing asyncStorage configuration');
        }
    }
    loadTable(table) {
        if (this.data[table] === undefined) {
            try {
                return (async () => {
                    const value = await AsyncStorage.getItem(table);
                    this.data[table] = value ? safeParse(value) : undefined;
                })();
            }
            catch (_a) {
                console.error('[legend-state] ObservablePersistLocalAsyncStorage failed to parse', table);
            }
        }
    }
    // Gets
    getTable(table, config, init) {
        var _a, _b;
        return (_b = (_a = this.data[table]) !== null && _a !== void 0 ? _a : init) !== null && _b !== void 0 ? _b : {};
    }
    getMetadata(table, config) {
        return this.getTable(table + MetadataSuffix, config, {});
    }
    // Sets
    set(table, changes) {
        if (!this.data[table]) {
            this.data[table] = {};
        }
        for (let i = 0; i < changes.length; i++) {
            const { path, valueAtPath, pathTypes } = changes[i];
            this.data[table] = setAtPath(this.data[table], path, pathTypes, valueAtPath);
        }
        return this.save(table);
    }
    setMetadata(table, metadata) {
        return this.setValue(table + MetadataSuffix, metadata);
    }
    async deleteTable(table) {
        return AsyncStorage.removeItem(table);
    }
    deleteMetadata(table) {
        return this.deleteTable(table + MetadataSuffix);
    }
    // Private
    async setValue(table, value) {
        this.data[table] = value;
        await this.save(table);
    }
    async save(table) {
        const v = this.data[table];
        if (v !== undefined && v !== null) {
            return AsyncStorage.setItem(table, safeStringify(v));
        }
        else {
            return AsyncStorage.removeItem(table);
        }
    }
}

export { ObservablePersistAsyncStorage };
//# sourceMappingURL=async-storage.mjs.map
