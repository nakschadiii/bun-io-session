import { ObservablePersistRemoteFunctions } from '@legendapp/state';
interface PersistFetchProps {
    get: string | RequestInfo;
    set?: string | RequestInfo;
    getInit?: RequestInit;
    setInit?: RequestInit;
    valueType?: 'arrayBuffer' | 'blob' | 'formData' | 'json' | 'text';
}
export declare function persistPluginFetch({ get, set, getInit, setInit, valueType, }: PersistFetchProps): ObservablePersistRemoteFunctions;
export {};
