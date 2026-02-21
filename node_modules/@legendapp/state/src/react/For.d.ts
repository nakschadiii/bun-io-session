import type { Observable, ObservableReadable } from '@legendapp/state';
import { FC, ReactElement } from 'react';
type ForItemProps<T, TProps = {}> = {
    item$: Observable<T>;
    id?: string;
} & TProps;
export declare function For<T, TProps>({ each, optimized: isOptimized, item, itemProps, sortValues, children, }: {
    each?: ObservableReadable<T[] | Record<any, T> | Map<any, T>>;
    optimized?: boolean;
    item?: FC<ForItemProps<T, TProps>>;
    itemProps?: TProps;
    sortValues?: (A: T, B: T, AKey: string, BKey: string) => number;
    children?: (value: Observable<T>, id: string | undefined) => ReactElement;
}): ReactElement | null;
export {};
