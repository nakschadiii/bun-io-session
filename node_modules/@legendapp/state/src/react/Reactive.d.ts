import { ComponentClass, FC } from 'react';
import { BindKeys } from './reactInterfaces';
export interface IReactive {
}
export declare const Reactive: IReactive;
export declare function configureReactive({ components, binders, }: {
    components?: Record<string, FC | ComponentClass<any>>;
    binders?: Record<string, BindKeys>;
}): void;
