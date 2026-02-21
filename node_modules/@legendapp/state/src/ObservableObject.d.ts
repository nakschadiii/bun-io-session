import type { GetOptions, NodeValue, ObservableObject, TrackingType } from './observableInterfaces';
export declare const observableProperties: Map<string, {
    get: (node: NodeValue, ...args: any[]) => any;
    set: (node: NodeValue, value: any) => any;
}>;
export declare const observableFns: Map<string, (node: NodeValue, ...args: any[]) => any>;
export declare function getProxy(node: NodeValue, p?: string): ObservableObject;
export declare function set(node: NodeValue, newValue?: any): any;
export declare function extractPromise(node: NodeValue, value: Promise<any>): void;
export declare function extractFunctionOrComputed(node: NodeValue, obj: Record<string, any>, k: string, v: any): true | undefined;
export declare function get(node: NodeValue, options?: TrackingType | GetOptions): any;
export declare function peek(node: NodeValue): any;
