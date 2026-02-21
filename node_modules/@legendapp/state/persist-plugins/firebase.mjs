import { observable, observablePrimitive, whenReady, isObject, mergeIntoObservable, isArray, when, constructObjectWithPath, deconstructObjectWithPath, batch, setAtPath, internal, hasOwnProperty } from '@legendapp/state';
import { transformPath, transformObject, internal as internal$1 } from '@legendapp/state/persist';
import { getAuth } from 'firebase/auth';
import { ref, getDatabase, query, orderByChild, startAt, update, onValue, onChildAdded, onChildChanged, serverTimestamp } from 'firebase/database';

const { symbolDelete, getPathType, clone } = internal;
const { observablePersistConfiguration } = internal$1;
function getDateModifiedKey(dateModifiedKey) {
    var _a;
    return dateModifiedKey || ((_a = observablePersistConfiguration.remoteOptions) === null || _a === void 0 ? void 0 : _a.dateModifiedKey) || '@';
}
const symbolSaveValue = Symbol('___obsSaveValue');
class ObservablePersistFirebaseBase {
    constructor(fns) {
        var _a, _b;
        this._batch = {};
        this._pathsLoadStatus = observable({});
        this.listenErrors = new Map();
        this.saveStates = new Map();
        this.fns = fns;
        this.user = observablePrimitive();
        this.SaveTimeout = (_b = (_a = observablePersistConfiguration === null || observablePersistConfiguration === void 0 ? void 0 : observablePersistConfiguration.remoteOptions) === null || _a === void 0 ? void 0 : _a.saveTimeout) !== null && _b !== void 0 ? _b : 500;
        if (this.fns.isInitialized()) {
            this.fns.onAuthStateChanged((user) => {
                this.user.set(user === null || user === void 0 ? void 0 : user.uid);
            });
        }
        else if (process.env.NODE_ENV === 'development' &&
            (typeof window !== 'undefined' || (typeof navigator !== 'undefined' && navigator.product === 'ReactNative'))) {
            // Warn only in web or react-native. If running on a server this shouldn't work.
            console.warn('[legend-state] Firebase is not initialized. Remote persistence will not work.');
        }
    }
    async get(params) {
        const { obs, options } = params;
        const { remote } = options;
        if (!remote || !remote.firebase) {
            // If the plugin is set globally but it has no firebase options this plugin can't do anything
            return;
        }
        const { firebase: { refPath }, waitForGet, } = remote;
        const { requireAuth, queryByModified } = options.remote.firebase;
        // If requireAuth wait for user to be signed in
        if (requireAuth) {
            await whenReady(this.user);
        }
        // If waitForGet wait for it
        if (waitForGet) {
            await whenReady(waitForGet);
        }
        const saveState = {
            pendingSaveResults: new Map(),
            pendingSaves: new Map(),
            numSavesPending: observable(0),
        };
        this.saveStates.set(obs, saveState);
        const pathFirebase = refPath(this.fns.getCurrentUser());
        const status$ = this._pathsLoadStatus[pathFirebase].set({
            startedLoading: false,
            numLoading: 0,
            numWaitingCanSave: 0,
        });
        const onLoadParams = {
            waiting: 0,
            onLoad: () => {
                onLoadParams.waiting--;
                if (onLoadParams.waiting === 0) {
                    params.onGet();
                }
            },
        };
        if (isObject(queryByModified)) {
            this.iterateListen(obs, params, saveState, [], [], queryByModified, onLoadParams, status$);
        }
        else {
            const dateModified = queryByModified === true ? params.dateModified : undefined;
            this._listen(obs, params, saveState, [], [], queryByModified, dateModified, onLoadParams, status$);
        }
    }
    iterateListen(obs, params, saveState, path, pathTypes, queryByModified, onLoadParams, status$) {
        const { options } = params;
        const { ignoreKeys } = options.remote.firebase;
        Object.keys(obs).forEach((key) => {
            if (!ignoreKeys || !ignoreKeys.includes(key)) {
                const o = obs[key];
                const q = queryByModified[key] || queryByModified['*'];
                const pathChild = path.concat(key);
                const pathTypesChild = pathTypes.concat(getPathType(o.peek()));
                let dateModified = undefined;
                if (isObject(q)) {
                    this.iterateListen(o, params, saveState, pathChild, pathTypesChild, q, onLoadParams, status$);
                }
                else {
                    if (q === true || q === '*') {
                        dateModified = params.dateModified;
                    }
                    this._listen(o, params, saveState, pathChild, pathTypesChild, queryByModified, dateModified, onLoadParams, status$);
                }
            }
        });
    }
    retryListens() {
        // If a listen failed but save succeeded, the save should have fixed
        // the permission problem so try again
        this.listenErrors.forEach((listenError) => {
            const { params, path, pathTypes, dateModified, queryByModified, unsubscribes, saveState, onLoadParams, status$, } = listenError;
            listenError.retry++;
            if (listenError.retry < 10) {
                unsubscribes.forEach((cb) => cb());
                this._listen(params.obs, params, saveState, path, pathTypes, queryByModified, dateModified, onLoadParams, status$);
            }
            else {
                this.listenErrors.delete(listenError);
            }
        });
    }
    async _listen(obs, params, saveState, path, pathTypes, queryByModified, dateModified, onLoadParams, status$) {
        const { options } = params;
        const { fieldTransforms, onGetError: onLoadError, allowSetIfError, firebase, dateModifiedKey: dateModifiedKeyOption, } = options.remote;
        const { refPath, query, mode } = firebase;
        let didError = false;
        const dateModifiedKey = getDateModifiedKey(dateModifiedKeyOption);
        const originalPath = path;
        if (fieldTransforms && path.length) {
            path = transformPath(path, pathTypes, fieldTransforms);
        }
        const pathFirebase = refPath(this.fns.getCurrentUser()) + path.join('/');
        let ref = this.fns.ref(pathFirebase);
        if (query) {
            ref = query(ref);
        }
        if (dateModified && !isNaN(dateModified)) {
            ref = this.fns.orderByChild(ref, dateModifiedKey, dateModified + 1);
        }
        const unsubscribes = [];
        status$.numLoading.set((v) => v + 1);
        status$.numWaitingCanSave.set((v) => v + 1);
        const _onError = (err) => {
            if (!didError) {
                didError = true;
                const existing = this.listenErrors.get(obs);
                if (existing) {
                    existing.retry++;
                }
                else {
                    this.listenErrors.set(obs, {
                        params,
                        path: originalPath,
                        pathTypes,
                        dateModified,
                        queryByModified,
                        unsubscribes,
                        retry: 0,
                        saveState,
                        onLoadParams,
                        status$,
                    });
                    params.state.error.set(err);
                    onLoadError === null || onLoadError === void 0 ? void 0 : onLoadError(err);
                    if (allowSetIfError) {
                        status$.numWaitingCanSave.set((v) => v - 1);
                    }
                }
            }
        };
        if (mode !== 'once') {
            const localState = { changes: {} };
            const cb = this._onChange.bind(this, path, pathTypes, pathFirebase, dateModifiedKey, dateModifiedKeyOption, params, localState, saveState, status$);
            unsubscribes.push(this.fns.onChildAdded(ref, cb));
            unsubscribes.push(this.fns.onChildChanged(ref, cb));
        }
        onLoadParams.waiting++;
        unsubscribes.push(this.fns.once(ref, this._onceValue.bind(this, path, pathTypes, pathFirebase, dateModifiedKey, dateModifiedKeyOption, queryByModified, onLoadParams.onLoad, params, status$), _onError));
    }
    _updatePendingSave(path, value, pending) {
        if (path.length === 0) {
            pending[symbolSaveValue] = value;
        }
        else if (pending[symbolSaveValue]) {
            pending[symbolSaveValue] = mergeIntoObservable(pending[symbolSaveValue], value);
        }
        else {
            const p = path[0];
            const v = value[p];
            const pendingChild = pending[p];
            // If already have a save info here then don't need to go deeper on the path. Just overwrite the value.
            if (pendingChild && pendingChild[symbolSaveValue] !== undefined) {
                const pendingSaveValue = pendingChild[symbolSaveValue];
                pendingChild[symbolSaveValue] =
                    isArray(pendingSaveValue) || isObject(pendingSaveValue)
                        ? mergeIntoObservable(pendingSaveValue, v)
                        : v;
            }
            else {
                // 1. If nothing here
                // 2. If other strings here
                if (!pending[p]) {
                    pending[p] = {};
                }
                if (path.length > 1) {
                    this._updatePendingSave(path.slice(1), v, pending[p]);
                }
                else {
                    pending[p] = { [symbolSaveValue]: v };
                }
            }
        }
    }
    async set({ options, changes, obs }) {
        const { remote } = options;
        // If the plugin is set globally but it has no firebase options this plugin can't do anything
        if (!remote || !remote.firebase) {
            return;
        }
        const { waitForSet, saveTimeout, log, firebase } = remote;
        const { requireAuth, refPath: refPathFn } = firebase;
        if (requireAuth) {
            await whenReady(this.user);
        }
        const refPath = refPathFn(this.fns.getCurrentUser());
        const status$ = this._pathsLoadStatus[refPath];
        if (status$.numWaitingCanSave.peek() > 0) {
            // Wait for all listened paths to load before we can save
            await when(() => status$.numWaitingCanSave.get() < 1);
        }
        if (waitForSet) {
            await whenReady(waitForSet);
        }
        const saveState = this.saveStates.get(obs);
        // Don't start a save until all outstanding saves are finished
        await when(() => saveState.numSavesPending.get() === 0);
        const { pendingSaveResults, pendingSaves } = saveState;
        if (!pendingSaves.has(refPath)) {
            pendingSaves.set(refPath, { options, saves: {} });
            pendingSaveResults.set(refPath, { saved: [] });
        }
        const pending = pendingSaves.get(refPath).saves;
        log === null || log === void 0 ? void 0 : log('verbose', 'Saving', changes);
        for (let i = 0; i < changes.length; i++) {
            let { valueAtPath } = changes[i];
            const { pathTypes, path } = changes[i];
            if (valueAtPath === undefined) {
                valueAtPath = null;
            }
            const value = constructObjectWithPath(path, pathTypes, clone(valueAtPath));
            const pathCloned = path.slice();
            this._updatePendingSave(pathCloned, value, pending);
        }
        if (!saveState.eventSaved) {
            saveState.eventSaved = observablePrimitive();
        }
        // Keep the current eventSaved. This will get reassigned once the timeout activates.
        const eventSaved = saveState.eventSaved;
        const timeout = saveTimeout !== null && saveTimeout !== void 0 ? saveTimeout : this.SaveTimeout;
        if (timeout) {
            if (saveState.timeout) {
                clearTimeout(saveState.timeout);
            }
            saveState.timeout = setTimeout(this._onTimeoutSave.bind(this, saveState), timeout);
        }
        else {
            this._onTimeoutSave(saveState);
        }
        const savedOrError = await when(eventSaved);
        if (savedOrError === true) {
            this.retryListens();
            const saveResults = pendingSaveResults.get(refPath);
            if (saveResults) {
                const { saved } = saveResults;
                if (saved === null || saved === void 0 ? void 0 : saved.length) {
                    // Only want to return from saved one time
                    if (saveState.numSavesPending.get() === 0) {
                        pendingSaveResults.delete(refPath);
                    }
                    else {
                        saveResults.saved = [];
                    }
                    let maxModified = 0;
                    // Compile a changes object of all the dateModified
                    const changesOut = {};
                    for (let i = 0; i < saved.length; i++) {
                        const { dateModified, path, pathTypes, dateModifiedKeyOption, dateModifiedKey, value } = saved[i];
                        if (dateModified) {
                            maxModified = Math.max(dateModified, maxModified);
                            if (dateModifiedKeyOption) {
                                const deconstructed = deconstructObjectWithPath(path, pathTypes, value);
                                // Don't resurrect deleted items
                                if (deconstructed !== symbolDelete) {
                                    Object.assign(changesOut, constructObjectWithPath(path, pathTypes, {
                                        [dateModifiedKey]: dateModified,
                                    }));
                                }
                            }
                        }
                    }
                    const ret = {
                        changes: changesOut,
                        dateModified: maxModified || undefined,
                    };
                    log === null || log === void 0 ? void 0 : log('verbose', 'Saved', changes, ret);
                    return ret;
                }
            }
        }
        else {
            throw savedOrError;
        }
        return {};
    }
    _constructBatch(options, batch, basePath, saves, ...path) {
        const { fieldTransforms, dateModifiedKey: dateModifiedKeyOption } = options.remote;
        const dateModifiedKey = getDateModifiedKey(dateModifiedKeyOption);
        let valSave = saves[symbolSaveValue];
        if (valSave !== undefined) {
            let queryByModified = options.remote.firebase.queryByModified;
            if (queryByModified) {
                if (queryByModified !== true && fieldTransforms) {
                    queryByModified = transformObject(queryByModified, fieldTransforms);
                }
                valSave = this.insertDatesToSave(batch, queryByModified, dateModifiedKey, basePath, path, valSave);
            }
            const pathThis = basePath + path.join('/');
            if (pathThis && !batch[pathThis]) {
                batch[pathThis] = valSave;
            }
        }
        else {
            Object.keys(saves).forEach((key) => {
                this._constructBatch(options, batch, basePath, saves[key], ...path, key);
            });
        }
    }
    _constructBatchesForSave(pendingSaves) {
        const batches = [];
        pendingSaves.forEach(({ options, saves }) => {
            const basePath = options.remote.firebase.refPath(this.fns.getCurrentUser());
            const batch = {};
            this._constructBatch(options, batch, basePath, saves);
            batches.push(batch);
        });
        return batches;
    }
    async _onTimeoutSave(saveState) {
        const { pendingSaves, eventSaved } = saveState;
        saveState.timeout = undefined;
        saveState.eventSaved = undefined;
        saveState.numSavesPending.set((v) => v + 1);
        if (pendingSaves.size > 0) {
            const batches = clone(this._constructBatchesForSave(pendingSaves));
            saveState.savingSaves = pendingSaves;
            // Clear the pendingSaves so that the next batch starts from scratch
            saveState.pendingSaves = new Map();
            if (batches.length > 0) {
                const promises = [];
                for (let i = 0; i < batches.length; i++) {
                    const batch = batches[i];
                    promises.push(this._saveBatch(batch));
                }
                const results = await Promise.all(promises);
                const errors = results.filter((result) => result.error);
                if (errors.length === 0) {
                    saveState.numSavesPending.set((v) => v - 1);
                    eventSaved === null || eventSaved === void 0 ? void 0 : eventSaved.set(true);
                }
                else {
                    eventSaved === null || eventSaved === void 0 ? void 0 : eventSaved.set(errors[0].error);
                }
            }
        }
    }
    async _saveBatch(batch) {
        const length = JSON.stringify(batch).length;
        let error = undefined;
        // Firebase has a maximum limit of 16MB per save so we constrain our saves to
        // less than 12 to be safe
        if (length > 12e6) {
            const parts = splitLargeObject(batch, 6e6);
            let didSave = true;
            // TODO: Option for logging
            for (let i = 0; i < parts.length; i++) {
                const ret = await this._saveBatch(parts[i]);
                if (ret.error) {
                    error = ret.error;
                }
                else {
                    didSave = didSave && ret.didSave;
                }
            }
            return error ? { error } : { didSave };
        }
        else {
            for (let i = 0; i < 3; i++) {
                try {
                    await this.fns.update(batch);
                    return { didSave: true };
                }
                catch (err) {
                    error = err;
                    await new Promise((resolve) => setTimeout(resolve, 500));
                }
            }
            return { error };
        }
    }
    _convertFBTimestamps(obj, dateModifiedKey, dateModifiedKeyOption) {
        let value = obj;
        // Database value can be either { @: number, _: object } or { @: number, ...rest }
        // where @ is the dateModifiedKey
        let dateModified = value[dateModifiedKey];
        if (dateModified) {
            // If user doesn't request a dateModifiedKey then delete it
            if (value._ !== undefined) {
                value = value._;
            }
            else if (dateModified && Object.keys(value).length < 2) {
                value = symbolDelete;
            }
            if (!dateModifiedKeyOption) {
                delete value[dateModifiedKey];
            }
        }
        if (isObject(value)) {
            Object.keys(value).forEach((k) => {
                const val = value[k];
                if (val !== undefined) {
                    if (isObject(val) || isArray(val)) {
                        const { value: valueChild, dateModified: dateModifiedChild } = this._convertFBTimestamps(val, dateModifiedKey, dateModifiedKeyOption);
                        if (dateModifiedChild) {
                            dateModified = Math.max(dateModified || 0, dateModifiedChild);
                        }
                        if (valueChild !== val) {
                            value[k] = valueChild;
                        }
                    }
                }
            });
        }
        return { value, dateModified };
    }
    async _onceValue(path, pathTypes, pathFirebase, dateModifiedKey, dateModifiedKeyOption, queryByModified, onLoad, params, status$, snapshot) {
        const { onChange } = params;
        const outerValue = snapshot.val();
        // If this path previously errored, clear the error state
        const obs = params.obs;
        params.state.error.delete();
        this.listenErrors.delete(obs);
        status$.startedLoading.set(true);
        if (outerValue && isObject(outerValue)) {
            let value;
            let dateModified;
            if (queryByModified) {
                const converted = this._convertFBTimestamps(outerValue, dateModifiedKey, dateModifiedKeyOption);
                value = converted.value;
                dateModified = converted.dateModified;
            }
            else {
                value = outerValue;
            }
            value = constructObjectWithPath(path, pathTypes, value);
            const onChangePromise = onChange({
                value,
                path,
                pathTypes,
                mode: queryByModified ? 'assign' : 'set',
                dateModified,
            });
            if (onChangePromise) {
                await onChangePromise;
            }
        }
        onLoad();
        batch(() => {
            status$.numLoading.set((v) => v - 1);
            status$.numWaitingCanSave.set((v) => v - 1);
        });
    }
    async _onChange(path, pathTypes, pathFirebase, dateModifiedKey, dateModifiedKeyOption, params, localState, saveState, status$, snapshot) {
        const { numLoading, startedLoading } = status$.peek();
        if (numLoading > 0) {
            // If onceValue has not been called yet, then skip onChange because it will come later
            if (!startedLoading)
                return;
            // Wait for load
            await when(() => status$.numLoading.get() < 1);
        }
        const { onChange, state, options: { remote }, } = params;
        const { changeTimeout } = remote;
        // Skip changes if disabled
        if (state.isEnabledRemote.peek() === false)
            return;
        const key = snapshot.key;
        const val = snapshot.val();
        if (val) {
            // eslint-disable-next-line prefer-const
            let { value, dateModified } = this._convertFBTimestamps(val, dateModifiedKey, dateModifiedKeyOption);
            const pathChild = path.concat(key);
            const pathTypesChild = pathTypes.concat('object');
            const constructed = constructObjectWithPath(pathChild, pathTypes, value);
            if (!this.addValuesToPendingSaves(pathFirebase, constructed, pathChild, pathTypesChild, dateModified, dateModifiedKey, dateModifiedKeyOption, saveState, onChange)) {
                localState.changes = setAtPath(localState.changes, pathChild, pathTypes, value);
                // Debounce many child changes into a single onChange
                clearTimeout(localState.timeout);
                localState.timeout = setTimeout(() => {
                    const changes = localState.changes;
                    localState.changes = {};
                    onChange({ value: changes, path, pathTypes, mode: 'assign', dateModified });
                }, changeTimeout || 300);
            }
        }
    }
    insertDateToObject(value, dateModifiedKey) {
        const timestamp = this.fns.serverTimestamp();
        if (isObject(value)) {
            return Object.assign(value, {
                [dateModifiedKey]: timestamp,
            });
        }
        else {
            return {
                [dateModifiedKey]: timestamp,
                _: value,
            };
        }
    }
    insertDatesToSaveObject(batch, queryByModified, dateModifiedKey, path, value) {
        if (queryByModified === true) {
            value = this.insertDateToObject(value, dateModifiedKey);
        }
        else if (isObject(value)) {
            Object.keys(value).forEach((key) => {
                value[key] = this.insertDatesToSaveObject(batch, queryByModified[key], dateModifiedKey, path + '/' + key, value[key]);
            });
        }
        return value;
    }
    insertDatesToSave(batch, queryByModified, dateModifiedKey, basePath, path, value) {
        let o = queryByModified;
        for (let i = 0; i < path.length; i++) {
            if (o === true) {
                const pathThis = basePath + path.slice(0, i + 1).join('/');
                if (i === path.length - 1) {
                    if (!isObject(value)) {
                        return this.insertDateToObject(value, dateModifiedKey);
                    }
                    else {
                        if (isObject(value)) {
                            value[dateModifiedKey] = this.fns.serverTimestamp();
                        }
                        else {
                            batch[pathThis + '/' + dateModifiedKey] = this.fns.serverTimestamp();
                        }
                    }
                }
                else {
                    batch[pathThis + '/' + dateModifiedKey] = this.fns.serverTimestamp();
                }
                return value;
            }
            else if (isObject(o)) {
                o = o[path[i]];
            }
        }
        if (o === true && isObject(value)) {
            Object.keys(value).forEach((key) => {
                this.insertDatesToSaveObject(batch, o, dateModifiedKey, basePath + path.join('/') + '/' + key, value[key]);
            });
        }
        else if (o !== undefined) {
            this.insertDatesToSaveObject(batch, o, dateModifiedKey, basePath + path.join('/'), value);
        }
        return value;
    }
    addValuesToPendingSaves(refPath, value, pathChild, pathTypesChild, dateModified, dateModifiedKey, dateModifiedKeyOption, saveState, onChange) {
        const { pendingSaveResults, savingSaves } = saveState;
        let found = false;
        const pathArr = refPath.split('/');
        for (let i = pathArr.length - 1; !found && i >= 0; i--) {
            const p = pathArr[i];
            if (p === '')
                continue;
            const path = pathArr.slice(0, i + 1).join('/') + '/';
            // Look for this saved key in the currently saving saves.
            // If it's being saved locally this must be the remote onChange
            // coming in for this save.
            if (pendingSaveResults.has(path) && (savingSaves === null || savingSaves === void 0 ? void 0 : savingSaves.has(path))) {
                found = true;
                if (pathChild.length > 0) {
                    const savingSave = savingSaves.get(path);
                    const save = savingSave.saves[pathChild[0]];
                    if (!save) {
                        found = false;
                    }
                }
                if (found) {
                    const pending = pendingSaveResults.get(path);
                    pending.saved.push({
                        value,
                        dateModified,
                        path: pathChild,
                        pathTypes: pathTypesChild,
                        dateModifiedKey,
                        dateModifiedKeyOption,
                        onChange,
                    });
                }
            }
            value = { [p]: value };
        }
        return found;
    }
}
function estimateSize(value) {
    return ('' + value).length + 2; // Convert to string and account for quotes in JSON.
}
function splitLargeObject(obj, limit) {
    const parts = [{}];
    let sizeCount = 0;
    function recursiveSplit(innerObj, path = []) {
        for (const key in innerObj) {
            if (!hasOwnProperty.call(innerObj, key)) {
                continue;
            }
            const newPath = [...path, key];
            const keySize = key.length + 4; // Account for quotes and colon in JSON.
            const val = innerObj[key];
            let itemSize = 0;
            if (val && typeof val === 'object') {
                itemSize = JSON.stringify(val).length;
            }
            else {
                itemSize = estimateSize(val);
            }
            if (val && typeof val === 'object' && itemSize > limit) {
                recursiveSplit(val, newPath);
            }
            else {
                // Check if the size of the current item exceeds the limit
                if (sizeCount > 0 && sizeCount + keySize + itemSize > limit) {
                    parts.push({});
                    sizeCount = 0;
                }
                const pathKey = newPath.join('/');
                parts[parts.length - 1][pathKey] = val;
                sizeCount += keySize + itemSize;
            }
        }
    }
    recursiveSplit(obj);
    return parts;
}
// This is the web version of all the firebase functions. It passes them in as arguments so that it could
// support firebase on other platforms.
class ObservablePersistFirebase extends ObservablePersistFirebaseBase {
    constructor() {
        super({
            isInitialized: () => {
                try {
                    return !!getAuth().app;
                }
                catch (_a) {
                    return false;
                }
            },
            getCurrentUser: () => { var _a; return (_a = getAuth().currentUser) === null || _a === void 0 ? void 0 : _a.uid; },
            ref: (path) => ref(getDatabase(), path),
            orderByChild: (ref, child, start) => query(ref, orderByChild(child), startAt(start)),
            update: (object) => update(ref(getDatabase()), object),
            once: (ref, callback, callbackError) => {
                let unsubscribe;
                const cb = (snap) => {
                    if (unsubscribe) {
                        unsubscribe();
                        unsubscribe = undefined;
                    }
                    callback(snap);
                };
                unsubscribe = onValue(ref, cb, callbackError);
                return unsubscribe;
            },
            onChildAdded,
            onChildChanged,
            serverTimestamp,
            onAuthStateChanged: (cb) => getAuth().onAuthStateChanged(cb),
        });
    }
}

export { ObservablePersistFirebase };
//# sourceMappingURL=firebase.mjs.map
