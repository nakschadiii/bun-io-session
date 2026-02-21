import type { ClassConstructor, FieldTransforms, Observable, ObservableObject, ObservablePersistLocal, ObservablePersistRemoteClass, ObservableWriteable, PersistOptions, PersistTransform, Primitive, TypeAtPath, WithPersistState } from '@legendapp/state';
export declare const mapPersistences: WeakMap<ClassConstructor<ObservablePersistLocal | ObservablePersistRemoteClass>, {
    persist: ObservablePersistLocal | ObservablePersistRemoteClass;
    initialized?: Observable<boolean>;
}>;
export declare const persistState: ObservableObject<{
    inRemoteSync: boolean;
}>;
export declare function transformOutData(value: any, path: string[], pathTypes: TypeAtPath[], { transform, fieldTransforms }: {
    transform?: PersistTransform;
    fieldTransforms?: FieldTransforms<any>;
}): {
    value: any;
    path: string[];
} | Promise<{
    value: any;
    path: string[];
}>;
export declare function transformLoadData(value: any, { transform, fieldTransforms }: {
    fieldTransforms?: FieldTransforms<any>;
    transform?: PersistTransform;
}, doUserTransform: boolean): Promise<any> | any;
export declare function onChangeRemote(cb: () => void): void;
export type WithoutState = any[] | Primitive | (Record<string, any> & {
    _state?: never;
});
export declare function persistObservable<T extends WithoutState>(observable: ObservableWriteable<T>, persistOptions: PersistOptions<T>): Observable<WithPersistState & T>;
export declare function persistObservable<T extends WithoutState>(initial: T | (() => T) | (() => Promise<T>), persistOptions: PersistOptions<T>): Observable<WithPersistState & T>;
