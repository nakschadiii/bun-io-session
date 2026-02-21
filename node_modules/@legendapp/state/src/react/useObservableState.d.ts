import { type Observable } from '@legendapp/state';
export declare function useObservableState<T>(initialValue?: T | (() => T) | (() => Promise<T>)): [Observable<T>, T];
