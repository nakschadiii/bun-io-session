import { type ObservablePrimitive } from '@legendapp/state';
type UndoRedoOptions = {
    limit?: number;
};
/**
 * Usage:
 *
 * Use this function to add undo/redo functionality to an observable.
 *
 * You can monitor how many undos or redos are available to enable/disable undo/redo
 * UI elements with undo$ and redo$.
 *
 * If you undo and then make a change, it'll delete any redos and add the change, as expected.
 *
 * If you don't pass in a limit, it will keep all history. This means it can grow indefinitely.
 *
 * ```typescript
 * const obs$ = observable({ test: 'hi', test2: 'a' });
 * const { undo, redo, undos$, redos$, getHistory } = undoRedo(obs$, { limit: 40 });
 * obs$.test.set('hello');
 * undo();
 * redo();
 * // observables for # of undos/redos available
 * undos$.get();
 * redos$.get();
 * ```
 */
export declare function undoRedo<T>(obs$: ObservablePrimitive<T>, options?: UndoRedoOptions): {
    undo(): void;
    redo(): void;
    undos$: import("@legendapp/state").ObservablePrimitiveBaseFns<number>;
    redos$: import("@legendapp/state").ObservablePrimitiveBaseFns<number>;
    getHistory: () => T[];
};
export {};
