'use strict';

var state = require('@legendapp/state');
var reactQuery = require('@tanstack/react-query');

function persistPluginQuery({ query: options, mutation: mutationOptions, type = 'Query', queryClient, useContext, }) {
    if (useContext) {
        queryClient = queryClient || reactQuery.useQueryClient();
    }
    // Set up the defaults like useBaseQuery does
    const defaultedOptions = queryClient.defaultQueryOptions(options);
    // Include callbacks in batch renders
    if (defaultedOptions.onError) {
        defaultedOptions.onError = reactQuery.notifyManager.batchCalls(defaultedOptions.onError);
    }
    if (defaultedOptions.onSuccess) {
        defaultedOptions.onSuccess = reactQuery.notifyManager.batchCalls(defaultedOptions.onSuccess);
    }
    if (defaultedOptions.onSettled) {
        defaultedOptions.onSettled = reactQuery.notifyManager.batchCalls(defaultedOptions.onSettled);
    }
    const Observer = type === 'Query' ? reactQuery.QueryObserver : reactQuery.InfiniteQueryObserver;
    const ret = {
        get({ onChange }) {
            let observer = undefined;
            let latestOptions = defaultedOptions;
            let queryKeyFromFn;
            const origQueryKey = options.queryKey;
            // If the queryKey is a function, observe it and extract the raw value
            const isKeyFunction = state.isFunction(origQueryKey);
            if (isKeyFunction) {
                state.observe(({ num }) => {
                    queryKeyFromFn = origQueryKey();
                    if (num > 0) {
                        updateQueryOptions(latestOptions);
                    }
                });
            }
            const updateQueryOptions = (obj) => {
                // Since legend-state mutates the query options, we need to clone it to make Query
                // see it as changed
                const options = Object.assign({}, obj);
                // Use the latest value from the observed queryKey function
                if (isKeyFunction) {
                    options.queryKey = queryKeyFromFn;
                }
                latestOptions = options;
                // Update the Query options
                if (observer) {
                    observer.setOptions(options, { listeners: false });
                }
            };
            updateQueryOptions(defaultedOptions);
            // Create the observer
            observer = new Observer(queryClient, latestOptions);
            // Get the initial optimistic results if it's already cached
            const result = observer.getOptimisticResult(latestOptions);
            // Subscribe to Query's observer and update the observable
            observer.subscribe((result) => {
                onChange({ value: result.data });
            });
            // Return the initial data
            if (result) {
                return result.data;
            }
        },
    };
    if (mutationOptions) {
        const mutator = new reactQuery.MutationObserver(queryClient, mutationOptions);
        // When the observable changes call the mutator function
        ret.set = async ({ value }) => {
            mutator.mutate(value);
        };
    }
    return ret;
}

exports.persistPluginQuery = persistPluginQuery;
//# sourceMappingURL=query.js.map
