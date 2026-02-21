import { ObservablePersistRemoteFunctions } from '@legendapp/state';
import { QueryClient, QueryKey, UseBaseQueryOptions, UseMutationOptions } from '@tanstack/react-query';
type ObservableQueryOptions<TQueryFnData, TError, TData, TQueryData, TQueryKey extends QueryKey> = Omit<UseBaseQueryOptions<TQueryFnData, TError, TData, TQueryData, TQueryKey>, 'queryKey'> & {
    queryKey?: TQueryKey | (() => TQueryKey);
};
type Params<TQueryFnData, TError, TData, TQueryData, TQueryKey extends QueryKey> = {
    query: ObservableQueryOptions<TQueryFnData, TError, TData, TQueryData, TQueryKey>;
    mutation?: UseMutationOptions<TData, TError, void>;
    type?: 'Query' | 'Infinite';
} & ({
    queryClient: QueryClient;
    useContext?: false | undefined | never;
} | {
    queryClient?: QueryClient;
    useContext?: true;
});
export declare function persistPluginQuery<TObs, TQueryFnData, TError, TData, TQueryData, TQueryKey extends QueryKey>({ query: options, mutation: mutationOptions, type, queryClient, useContext, }: Params<TQueryFnData, TError, TData, TQueryData, TQueryKey>): ObservablePersistRemoteFunctions<TObs>;
export {};
