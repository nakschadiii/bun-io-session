import type { NodeValue } from './observableInterfaces';
export declare function notify(node: NodeValue, value: any, prev: any, level: number, whenOptimizedOnlyIf?: boolean): void;
export declare function runBatch(): void;
export declare function batch(fn: () => void, onComplete?: () => void): void;
export declare function beginBatch(): void;
export declare function endBatch(force?: boolean): void;
