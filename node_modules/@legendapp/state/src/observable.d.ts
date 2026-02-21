import type { Observable, ObservablePrimitive, WithState } from './observableInterfaces';
export declare function observable<T>(value: Promise<T>): Observable<T & WithState>;
export declare function observable<T>(value?: T): Observable<T>;
export declare function observablePrimitive<T>(value: Promise<T>): ObservablePrimitive<T & WithState>;
export declare function observablePrimitive<T>(value?: T): ObservablePrimitive<T>;
