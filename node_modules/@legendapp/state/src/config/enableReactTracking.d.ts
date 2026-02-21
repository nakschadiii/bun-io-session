import { type TrackingType } from '@legendapp/state';
interface ReactTrackingOptions {
    auto?: boolean;
    warnUnobserved?: boolean;
}
export declare function enableReactTracking({ auto, warnUnobserved }: ReactTrackingOptions): void;
import type { GetOptions } from '@legendapp/state';
declare module '@legendapp/state' {
    interface ObservableBaseFns<T> {
        get(options?: TrackingType | (GetOptions & {
            suspense?: boolean;
        })): T;
    }
}
export {};
