import type { ObservableObjectOrArray, ObservablePrimitive } from './observableInterfaces';
export declare function createObservable<T>(value: T | undefined, makePrimitive: boolean, createObject: Function, createPrimitive?: Function): ObservablePrimitive<T> | ObservableObjectOrArray<T>;
