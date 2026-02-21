import type { ObservablePersistRemoteClass, ObservablePersistRemoteFunctions } from '@legendapp/state';
export declare function observablePersistRemoteFunctionsAdapter<T = {}>({ get, set, }: ObservablePersistRemoteFunctions<T>): ObservablePersistRemoteClass;
