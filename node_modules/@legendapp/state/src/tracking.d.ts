import type { NodeValue, TrackingNode, TrackingType } from './observableInterfaces';
interface TrackingState {
    nodes?: Map<NodeValue, TrackingNode>;
    traceListeners?: (nodes: Map<NodeValue, TrackingNode>) => void;
    traceUpdates?: (fn: Function) => Function;
}
export declare const tracking: {
    current: TrackingState | undefined;
};
export declare function beginTracking(): void;
export declare function endTracking(): void;
export declare function updateTracking(node: NodeValue, track?: TrackingType): void;
export {};
