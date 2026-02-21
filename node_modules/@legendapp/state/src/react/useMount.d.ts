export declare function useMount(fn: () => (void | (() => void)) | Promise<void>): void;
export declare const useMountOnce: (effect: () => void | (() => void)) => void;
