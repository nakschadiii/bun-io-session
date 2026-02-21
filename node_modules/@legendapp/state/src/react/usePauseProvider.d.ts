import { ReactNode } from 'react';
export declare const PauseContext: import("react").Context<import("@legendapp/state").ObservablePrimitiveBaseFns<boolean> & import("@legendapp/state").ObservablePrimitiveBooleanFns<boolean>>;
export declare function usePauseProvider(): {
    PauseProvider: ({ children }: {
        children: ReactNode;
    }) => import("react").FunctionComponentElement<import("react").ProviderProps<import("@legendapp/state").ObservablePrimitiveBaseFns<boolean> & import("@legendapp/state").ObservablePrimitiveBooleanFns<boolean>>>;
    isPaused$: import("@legendapp/state").ObservablePrimitiveBaseFns<boolean> & import("@legendapp/state").ObservablePrimitiveBooleanFns<boolean>;
};
