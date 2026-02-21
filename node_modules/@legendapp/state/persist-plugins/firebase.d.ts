import { ObservablePersistRemoteClass, ObservablePersistRemoteGetParams, ObservablePersistRemoteSetParams } from '@legendapp/state';
import { type User } from 'firebase/auth';
import type { DataSnapshot } from 'firebase/database';
import { DatabaseReference } from 'firebase/database';
interface FirebaseFns {
    isInitialized: () => boolean;
    getCurrentUser: () => string | undefined;
    ref: (path: string) => DatabaseReference;
    orderByChild: (ref: any, child: string, startAt: number) => any;
    once: (query: any, callback: (snapshot: DataSnapshot) => unknown, onError: (error: Error) => void) => () => void;
    onChildAdded: (query: any, callback: (snapshot: DataSnapshot) => unknown, cancelCallback?: (error: Error) => unknown) => () => void;
    onChildChanged: (query: any, callback: (snapshot: DataSnapshot) => unknown, cancelCallback?: (error: Error) => unknown) => () => void;
    serverTimestamp: () => any;
    update: (object: object) => Promise<void>;
    onAuthStateChanged: (cb: (user: User | null) => void) => void;
}
declare class ObservablePersistFirebaseBase implements ObservablePersistRemoteClass {
    protected _batch: Record<string, any>;
    protected fns: FirebaseFns;
    private _pathsLoadStatus;
    private SaveTimeout;
    private user;
    private listenErrors;
    private saveStates;
    constructor(fns: FirebaseFns);
    get<T>(params: ObservablePersistRemoteGetParams<T>): Promise<void>;
    private iterateListen;
    private retryListens;
    private _listen;
    private _updatePendingSave;
    set<T>({ options, changes, obs }: ObservablePersistRemoteSetParams<T>): Promise<{
        changes?: object;
        dateModified?: number;
        pathStrs?: string[];
    } | undefined>;
    private _constructBatch;
    private _constructBatchesForSave;
    private _onTimeoutSave;
    private _saveBatch;
    private _convertFBTimestamps;
    private _onceValue;
    private _onChange;
    private insertDateToObject;
    private insertDatesToSaveObject;
    private insertDatesToSave;
    private addValuesToPendingSaves;
}
export declare class ObservablePersistFirebase extends ObservablePersistFirebaseBase {
    constructor();
}
export {};
