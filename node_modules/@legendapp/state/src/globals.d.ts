import { NodeValue, ObservableComputed, ObservableReadable } from './observableInterfaces';
export declare const symbolToPrimitive: symbol;
export declare const symbolGetNode: unique symbol;
export declare const symbolDelete: unique symbol;
export declare const symbolOpaque: unique symbol;
export declare const optimized: unique symbol;
export declare const extraPrimitiveActivators: Map<string | symbol, boolean>;
export declare const extraPrimitiveProps: Map<string | symbol, any>;
export declare const globalState: {
    isLoadingLocal: boolean;
    isLoadingRemote: boolean;
    isMerging: boolean;
};
export declare function checkActivate(node: NodeValue): void;
export declare function getNode(obs: ObservableReadable): NodeValue;
export declare function setNodeValue(node: NodeValue, newValue: any): {
    prevValue: any;
    newValue: any;
    parentValue: any;
};
export declare function getNodeValue(node: NodeValue): any;
export declare function getChildNode(node: NodeValue, key: string): NodeValue;
export declare function ensureNodeValue(node: NodeValue): any;
export declare function findIDKey(obj: unknown | undefined, node: NodeValue): string | ((value: any) => string) | undefined;
export declare function extractFunction(node: NodeValue, key: string, fnOrComputed: Function, computedChildNode?: never): void;
export declare function extractFunction(node: NodeValue, key: string, fnOrComputed: ObservableComputed, computedChildNode: NodeValue): void;
