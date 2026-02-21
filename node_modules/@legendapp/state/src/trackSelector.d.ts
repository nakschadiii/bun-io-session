import type { ListenerParams, ObserveEvent, Selector } from './observableInterfaces';
import type { ObserveOptions } from './observe';
export declare function trackSelector<T>(selector: Selector<T>, update: (params: ListenerParams) => void, observeEvent?: ObserveEvent<T>, observeOptions?: ObserveOptions, createResubscribe?: boolean): {
    value: any;
    dispose: (() => void) | undefined;
    resubscribe: (() => () => void) | undefined;
};
