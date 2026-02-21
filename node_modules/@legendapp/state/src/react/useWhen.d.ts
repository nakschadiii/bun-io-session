import { Selector } from '@legendapp/state';
export declare function useWhen<T>(predicate: Selector<T>, effect: (value: T) => any | (() => any)): Promise<T>;
export declare function useWhenReady<T>(predicate: Selector<T>, effect: (value: T) => any | (() => any)): Promise<T>;
