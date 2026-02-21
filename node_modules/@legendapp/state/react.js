'use strict';

var state = require('@legendapp/state');
var require$$0 = require('react');

var shim = {exports: {}};

var useSyncExternalStoreShim_production_min = {};

/**
 * @license React
 * use-sync-external-store-shim.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

var hasRequiredUseSyncExternalStoreShim_production_min;

function requireUseSyncExternalStoreShim_production_min () {
	if (hasRequiredUseSyncExternalStoreShim_production_min) return useSyncExternalStoreShim_production_min;
	hasRequiredUseSyncExternalStoreShim_production_min = 1;
var e=require$$0;function h(a,b){return a===b&&(0!==a||1/a===1/b)||a!==a&&b!==b}var k="function"===typeof Object.is?Object.is:h,l=e.useState,m=e.useEffect,n=e.useLayoutEffect,p=e.useDebugValue;function q(a,b){var d=b(),f=l({inst:{value:d,getSnapshot:b}}),c=f[0].inst,g=f[1];n(function(){c.value=d;c.getSnapshot=b;r(c)&&g({inst:c});},[a,d,b]);m(function(){r(c)&&g({inst:c});return a(function(){r(c)&&g({inst:c});})},[a]);p(d);return d}
	function r(a){var b=a.getSnapshot;a=a.value;try{var d=b();return !k(a,d)}catch(f){return !0}}function t(a,b){return b()}var u="undefined"===typeof window||"undefined"===typeof window.document||"undefined"===typeof window.document.createElement?t:q;useSyncExternalStoreShim_production_min.useSyncExternalStore=void 0!==e.useSyncExternalStore?e.useSyncExternalStore:u;
	return useSyncExternalStoreShim_production_min;
}

var useSyncExternalStoreShim_development = {};

/**
 * @license React
 * use-sync-external-store-shim.development.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

var hasRequiredUseSyncExternalStoreShim_development;

function requireUseSyncExternalStoreShim_development () {
	if (hasRequiredUseSyncExternalStoreShim_development) return useSyncExternalStoreShim_development;
	hasRequiredUseSyncExternalStoreShim_development = 1;

	if (process.env.NODE_ENV !== "production") {
	  (function() {

	/* global __REACT_DEVTOOLS_GLOBAL_HOOK__ */
	if (
	  typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined' &&
	  typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart ===
	    'function'
	) {
	  __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStart(new Error());
	}
	          var React = require$$0;

	var ReactSharedInternals = React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;

	function error(format) {
	  {
	    {
	      for (var _len2 = arguments.length, args = new Array(_len2 > 1 ? _len2 - 1 : 0), _key2 = 1; _key2 < _len2; _key2++) {
	        args[_key2 - 1] = arguments[_key2];
	      }

	      printWarning('error', format, args);
	    }
	  }
	}

	function printWarning(level, format, args) {
	  // When changing this logic, you might want to also
	  // update consoleWithStackDev.www.js as well.
	  {
	    var ReactDebugCurrentFrame = ReactSharedInternals.ReactDebugCurrentFrame;
	    var stack = ReactDebugCurrentFrame.getStackAddendum();

	    if (stack !== '') {
	      format += '%s';
	      args = args.concat([stack]);
	    } // eslint-disable-next-line react-internal/safe-string-coercion


	    var argsWithFormat = args.map(function (item) {
	      return String(item);
	    }); // Careful: RN currently depends on this prefix

	    argsWithFormat.unshift('Warning: ' + format); // We intentionally don't use spread (or .apply) directly because it
	    // breaks IE9: https://github.com/facebook/react/issues/13610
	    // eslint-disable-next-line react-internal/no-production-logging

	    Function.prototype.apply.call(console[level], console, argsWithFormat);
	  }
	}

	/**
	 * inlined Object.is polyfill to avoid requiring consumers ship their own
	 * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/is
	 */
	function is(x, y) {
	  return x === y && (x !== 0 || 1 / x === 1 / y) || x !== x && y !== y // eslint-disable-line no-self-compare
	  ;
	}

	var objectIs = typeof Object.is === 'function' ? Object.is : is;

	// dispatch for CommonJS interop named imports.

	var useState = React.useState,
	    useEffect = React.useEffect,
	    useLayoutEffect = React.useLayoutEffect,
	    useDebugValue = React.useDebugValue;
	var didWarnOld18Alpha = false;
	var didWarnUncachedGetSnapshot = false; // Disclaimer: This shim breaks many of the rules of React, and only works
	// because of a very particular set of implementation details and assumptions
	// -- change any one of them and it will break. The most important assumption
	// is that updates are always synchronous, because concurrent rendering is
	// only available in versions of React that also have a built-in
	// useSyncExternalStore API. And we only use this shim when the built-in API
	// does not exist.
	//
	// Do not assume that the clever hacks used by this hook also work in general.
	// The point of this shim is to replace the need for hacks by other libraries.

	function useSyncExternalStore(subscribe, getSnapshot, // Note: The shim does not use getServerSnapshot, because pre-18 versions of
	// React do not expose a way to check if we're hydrating. So users of the shim
	// will need to track that themselves and return the correct value
	// from `getSnapshot`.
	getServerSnapshot) {
	  {
	    if (!didWarnOld18Alpha) {
	      if (React.startTransition !== undefined) {
	        didWarnOld18Alpha = true;

	        error('You are using an outdated, pre-release alpha of React 18 that ' + 'does not support useSyncExternalStore. The ' + 'use-sync-external-store shim will not work correctly. Upgrade ' + 'to a newer pre-release.');
	      }
	    }
	  } // Read the current snapshot from the store on every render. Again, this
	  // breaks the rules of React, and only works here because of specific
	  // implementation details, most importantly that updates are
	  // always synchronous.


	  var value = getSnapshot();

	  {
	    if (!didWarnUncachedGetSnapshot) {
	      var cachedValue = getSnapshot();

	      if (!objectIs(value, cachedValue)) {
	        error('The result of getSnapshot should be cached to avoid an infinite loop');

	        didWarnUncachedGetSnapshot = true;
	      }
	    }
	  } // Because updates are synchronous, we don't queue them. Instead we force a
	  // re-render whenever the subscribed state changes by updating an some
	  // arbitrary useState hook. Then, during render, we call getSnapshot to read
	  // the current value.
	  //
	  // Because we don't actually use the state returned by the useState hook, we
	  // can save a bit of memory by storing other stuff in that slot.
	  //
	  // To implement the early bailout, we need to track some things on a mutable
	  // object. Usually, we would put that in a useRef hook, but we can stash it in
	  // our useState hook instead.
	  //
	  // To force a re-render, we call forceUpdate({inst}). That works because the
	  // new object always fails an equality check.


	  var _useState = useState({
	    inst: {
	      value: value,
	      getSnapshot: getSnapshot
	    }
	  }),
	      inst = _useState[0].inst,
	      forceUpdate = _useState[1]; // Track the latest getSnapshot function with a ref. This needs to be updated
	  // in the layout phase so we can access it during the tearing check that
	  // happens on subscribe.


	  useLayoutEffect(function () {
	    inst.value = value;
	    inst.getSnapshot = getSnapshot; // Whenever getSnapshot or subscribe changes, we need to check in the
	    // commit phase if there was an interleaved mutation. In concurrent mode
	    // this can happen all the time, but even in synchronous mode, an earlier
	    // effect may have mutated the store.

	    if (checkIfSnapshotChanged(inst)) {
	      // Force a re-render.
	      forceUpdate({
	        inst: inst
	      });
	    }
	  }, [subscribe, value, getSnapshot]);
	  useEffect(function () {
	    // Check for changes right before subscribing. Subsequent changes will be
	    // detected in the subscription handler.
	    if (checkIfSnapshotChanged(inst)) {
	      // Force a re-render.
	      forceUpdate({
	        inst: inst
	      });
	    }

	    var handleStoreChange = function () {
	      // TODO: Because there is no cross-renderer API for batching updates, it's
	      // up to the consumer of this library to wrap their subscription event
	      // with unstable_batchedUpdates. Should we try to detect when this isn't
	      // the case and print a warning in development?
	      // The store changed. Check if the snapshot changed since the last time we
	      // read from the store.
	      if (checkIfSnapshotChanged(inst)) {
	        // Force a re-render.
	        forceUpdate({
	          inst: inst
	        });
	      }
	    }; // Subscribe to the store and return a clean-up function.


	    return subscribe(handleStoreChange);
	  }, [subscribe]);
	  useDebugValue(value);
	  return value;
	}

	function checkIfSnapshotChanged(inst) {
	  var latestGetSnapshot = inst.getSnapshot;
	  var prevValue = inst.value;

	  try {
	    var nextValue = latestGetSnapshot();
	    return !objectIs(prevValue, nextValue);
	  } catch (error) {
	    return true;
	  }
	}

	function useSyncExternalStore$1(subscribe, getSnapshot, getServerSnapshot) {
	  // Note: The shim does not use getServerSnapshot, because pre-18 versions of
	  // React do not expose a way to check if we're hydrating. So users of the shim
	  // will need to track that themselves and return the correct value
	  // from `getSnapshot`.
	  return getSnapshot();
	}

	var canUseDOM = !!(typeof window !== 'undefined' && typeof window.document !== 'undefined' && typeof window.document.createElement !== 'undefined');

	var isServerEnvironment = !canUseDOM;

	var shim = isServerEnvironment ? useSyncExternalStore$1 : useSyncExternalStore;
	var useSyncExternalStore$2 = React.useSyncExternalStore !== undefined ? React.useSyncExternalStore : shim;

	useSyncExternalStoreShim_development.useSyncExternalStore = useSyncExternalStore$2;
	          /* global __REACT_DEVTOOLS_GLOBAL_HOOK__ */
	if (
	  typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined' &&
	  typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop ===
	    'function'
	) {
	  __REACT_DEVTOOLS_GLOBAL_HOOK__.registerInternalModuleStop(new Error());
	}
	        
	  })();
	}
	return useSyncExternalStoreShim_development;
}

(function (module) {

	if (process.env.NODE_ENV === 'production') {
	  module.exports = requireUseSyncExternalStoreShim_production_min();
	} else {
	  module.exports = requireUseSyncExternalStoreShim_development();
	}
} (shim));

const reactGlobals = {
    inObserver: false,
};

const PauseContext = require$$0.createContext(null);
function usePauseProvider() {
    const [value] = require$$0.useState(() => state.observable(false));
    return {
        PauseProvider: ({ children }) => require$$0.createElement(PauseContext.Provider, { value }, children),
        isPaused$: value,
    };
}

function createSelectorFunctions(options, isPaused$) {
    let version = 0;
    let notify;
    let dispose;
    let resubscribe;
    let _selector;
    let prev;
    let pendingUpdate = undefined;
    const run = () => {
        // Dispose if already listening
        dispose === null || dispose === void 0 ? void 0 : dispose();
        const { value, dispose: _dispose, resubscribe: _resubscribe, } = state.trackSelector(_selector, _update, undefined, undefined, /*createResubscribe*/ true);
        dispose = _dispose;
        resubscribe = _resubscribe;
        return value;
    };
    const _update = ({ value }) => {
        if (isPaused$ === null || isPaused$ === void 0 ? void 0 : isPaused$.peek()) {
            const next = pendingUpdate;
            pendingUpdate = value;
            if (next === undefined) {
                state.when(() => !isPaused$.get(), () => {
                    const latest = pendingUpdate;
                    pendingUpdate = undefined;
                    _update({ value: latest });
                });
            }
        }
        else {
            // If skipCheck then don't need to re-run selector
            let changed = options === null || options === void 0 ? void 0 : options.skipCheck;
            if (!changed) {
                const newValue = run();
                // If newValue is different than previous value then it's changed.
                // Also if the selector returns an observable directly then its value will be the same as
                // the value from the listener, and that should always re-render.
                if (newValue !== prev || (!state.isPrimitive(newValue) && newValue === value)) {
                    changed = true;
                }
            }
            if (changed) {
                version++;
                notify === null || notify === void 0 ? void 0 : notify();
            }
        }
    };
    return {
        subscribe: (onStoreChange) => {
            notify = onStoreChange;
            // Workaround for React 18 running twice in dev (part 2)
            if ((process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') &&
                !dispose &&
                resubscribe) {
                dispose = resubscribe();
            }
            return () => {
                dispose === null || dispose === void 0 ? void 0 : dispose();
                dispose = undefined;
            };
        },
        getVersion: () => version,
        run: (selector) => {
            // Update the cached selector
            _selector = selector;
            return (prev = run());
        },
    };
}
function useSelector(selector, options) {
    var _a;
    // Short-circuit to skip creating the hook if selector is an observable
    // and running in an observer. If selector is a function it needs to run in its own context.
    if (reactGlobals.inObserver && state.isObservable(selector) && !(options === null || options === void 0 ? void 0 : options.suspense)) {
        return state.computeSelector(selector);
    }
    let value;
    try {
        const isPaused$ = require$$0.useContext(PauseContext);
        const selectorFn = require$$0.useMemo(() => createSelectorFunctions(options, isPaused$), []);
        const { subscribe, getVersion, run } = selectorFn;
        // Run the selector
        // Note: The selector needs to run on every render because it may have different results
        // than the previous run if it uses local state
        value = run(selector);
        shim.exports.useSyncExternalStore(subscribe, getVersion, getVersion);
        // Suspense support
        if (options === null || options === void 0 ? void 0 : options.suspense) {
            // Note: Although it's not possible for an observable to be a promise, the selector may be a
            // function that returns a Promise, so we handle that case too.
            if (state.isPromise(value) ||
                (!value &&
                    state.isObservable(selector) &&
                    !selector.state.isLoaded.get())) {
                if (require$$0.use) {
                    require$$0.use(value);
                }
                else {
                    throw value;
                }
            }
        }
    }
    catch (err) {
        if ((process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') &&
            ((_a = err === null || err === void 0 ? void 0 : err.message) === null || _a === void 0 ? void 0 : _a.includes('Rendered more'))) {
            console.warn(`[legend-state]: You may want to wrap this component in \`observer\` to fix the error of ${err.message}`);
        }
        throw err;
    }
    return value;
}

function Computed({ children }) {
    return useSelector(() => state.computeSelector(state.computeSelector(children)), { skipCheck: true });
}

// Extracting the forwardRef inspired by https://github.com/mobxjs/mobx/blob/main/packages/mobx-react-lite/src/observer.ts
const hasSymbol =  typeof Symbol === 'function' && Symbol.for;
// TODOV2: Change bindKeys to an options object, where one of the options is "convertChildren" so that behavior can be optional
function createReactiveComponent(component, observe, reactive, bindKeys) {
    const ReactForwardRefSymbol = hasSymbol
        ? Symbol.for('react.forward_ref')
        : // eslint-disable-next-line react/display-name, @typescript-eslint/no-unused-vars
            typeof require$$0.forwardRef === 'function' && require$$0.forwardRef((props) => null)['$$typeof'];
    const ReactMemoSymbol = hasSymbol
        ? Symbol.for('react.memo')
        : // eslint-disable-next-line react/display-name, @typescript-eslint/no-unused-vars
            typeof require$$0.forwardRef === 'function' && require$$0.memo((props) => null)['$$typeof'];
    // If this component is already reactive bail out early
    // This can happen with Fast Refresh.
    if (component['__legend_proxied'])
        return component;
    let useForwardRef = false;
    let useMemo = false;
    let render = component;
    // Unwrap memo on the component
    if (ReactMemoSymbol && render['$$typeof'] === ReactMemoSymbol && render['type']) {
        useMemo = true;
        render = render['type'];
    }
    // Unwrap forwardRef on the component
    if (ReactForwardRefSymbol && render['$$typeof'] === ReactForwardRefSymbol) {
        useForwardRef = true;
        render = render['render'];
        if (process.env.NODE_ENV === 'development' && typeof render !== 'function') {
            throw new Error(`[legend-state] \`render\` property of ForwardRef was not a function`);
        }
    }
    const proxyHandler = {
        apply(target, thisArg, argArray) {
            // If this is a reactive component, convert all props ending in $
            // to regular props and set up a useSelector listener
            if (reactive) {
                const props = argArray[0];
                const propsOut = {};
                const keys = Object.keys(props);
                for (let i = 0; i < keys.length; i++) {
                    const key = keys[i];
                    const p = props[key];
                    // Convert children if it's a function
                    if (key === 'children' && (state.isFunction(p) || state.isObservable(p))) {
                        props[key] = useSelector(p, { skipCheck: true });
                    }
                    // Convert reactive props
                    else if (key.startsWith('$') || key.endsWith('$')) {
                        // TODOV3 Add this warning and then remove the deprecated endsWith option
                        // if (
                        //     process.env.NODE_ENV === 'development' &&
                        //     !internal.globalState.noDepWarn &&
                        //     key.endsWith('$')
                        // ) {
                        //     console.warn(
                        //         `[legend-state] Reactive props will be changed to start with $ instead of end with $ in version 2.0. So please change ${key} to $${key.replace(
                        //             '$',
                        //             '',
                        //         )}. See https://legendapp.com/open-source/state/migrating for more details.`,
                        //     );
                        // }
                        const k = key.endsWith('$') ? key.slice(0, -1) : key.slice(1);
                        // Return raw value and listen to the selector for changes
                        const bind = bindKeys === null || bindKeys === void 0 ? void 0 : bindKeys[k];
                        const shouldBind = bind && state.isObservable(p);
                        propsOut[k] = shouldBind && (bind === null || bind === void 0 ? void 0 : bind.selector) ? bind.selector(propsOut, p) : useSelector(p);
                        // If this key is one of the bind keys set up a two-way binding
                        if (shouldBind) {
                            // Use the bind's defaultValue if value is undefined
                            if (bind.defaultValue !== undefined && propsOut[k] === undefined) {
                                propsOut[k] = bind.defaultValue;
                            }
                            if (bind.handler && bind.getValue) {
                                // Hook up the change lander
                                const handlerFn = (e) => {
                                    var _a;
                                    p.set(bind.getValue(e));
                                    (_a = props[bind.handler]) === null || _a === void 0 ? void 0 : _a.call(props, e);
                                };
                                propsOut[bind.handler] =
                                    // If in development mode, don't memoize the handler. fix fast refresh bug
                                    process.env.NODE_ENV === 'development'
                                        ? handlerFn
                                        : require$$0.useCallback(handlerFn, [props[bind.handler], bindKeys]);
                            }
                        }
                        // Delete the reactive key
                        delete propsOut[key];
                    }
                    else if (propsOut[key] === undefined) {
                        propsOut[key] = p;
                    }
                }
                argArray[0] = propsOut;
            }
            // If observing wrap the whole render in a useSelector to listen to it
            if (observe) {
                return useSelector(() => {
                    reactGlobals.inObserver = true;
                    try {
                        return Reflect.apply(target, thisArg, argArray);
                    }
                    finally {
                        reactGlobals.inObserver = false;
                    }
                }, { skipCheck: true });
            }
            else {
                return Reflect.apply(target, thisArg, argArray);
            }
        },
    };
    const proxy = new Proxy(render, proxyHandler);
    let ret;
    if (useForwardRef) {
        ret = require$$0.forwardRef(proxy);
        ret['__legend_proxied'] = true;
    }
    else {
        ret = proxy;
    }
    return observe || useMemo ? require$$0.memo(ret) : ret;
}
function observer(component) {
    return createReactiveComponent(component, true);
}
function reactive(component, bindKeys) {
    return createReactiveComponent(component, false, true, bindKeys);
}
function reactiveObserver(component, bindKeys) {
    return createReactiveComponent(component, true, true, bindKeys);
}
function reactiveComponents(components) {
    return new Proxy({}, {
        get(target, p) {
            if (!target[p] && components[p]) {
                target[p] = createReactiveComponent(components[p], false, true);
            }
            return target[p];
        },
    });
}

const autoMemoCache = new Map();
function For({ each, optimized: isOptimized, item, itemProps, sortValues, children, }) {
    var _a;
    if (!each)
        return null;
    // Get the raw value with a shallow listener so this list only re-renders
    // when the array length changes
    const value = useSelector(() => each.get(isOptimized ? state.optimized : true));
    // The child function gets wrapped in a memoized observer component
    if (!item && children) {
        // Update the ref so the generated component uses the latest function
        const refChildren = require$$0.useRef();
        refChildren.current = children;
        item = require$$0.useMemo(() => observer(({ item$, id }) => refChildren.current(item$, id)), []);
    }
    else {
        // @ts-expect-error $$typeof is private
        if (item.$$typeof !== Symbol.for('react.memo')) {
            let memod = autoMemoCache.get(item);
            if (!memod) {
                memod = require$$0.memo(item);
                autoMemoCache.set(item, memod);
            }
            item = memod;
        }
    }
    // This early out needs to be after any hooks
    if (!value)
        return null;
    // Create the child elements
    const out = [];
    const isArr = state.isArray(value);
    if (isArr) {
        // Get the appropriate id field
        const v0 = value[0];
        const node = state.getNode(each);
        const length = value.length;
        const idField = length > 0
            ? (node && state.findIDKey(v0, node)) ||
                (v0.id !== undefined ? 'id' : v0.key !== undefined ? 'key' : undefined)
            : undefined;
        const isIdFieldFunction = state.isFunction(idField);
        for (let i = 0; i < length; i++) {
            if (value[i]) {
                const val = value[i];
                const key = (_a = (isIdFieldFunction ? idField(val) : val[idField])) !== null && _a !== void 0 ? _a : i;
                const item$ = each[i];
                // TODOV3 Remove item
                const props = {
                    key,
                    id: key,
                    item$,
                    item: item$,
                };
                out.push(require$$0.createElement(item, itemProps ? Object.assign(props, itemProps) : props));
            }
        }
    }
    else {
        // Render the values of the object / Map
        const isMap = value instanceof Map;
        const keys = isMap ? Array.from(value.keys()) : Object.keys(value);
        if (sortValues) {
            keys.sort((A, B) => sortValues(isMap ? value.get(A) : value[A], isMap ? value.get(B) : value[B], A, B));
        }
        for (let i = 0; i < keys.length; i++) {
            const key = keys[i];
            if (isMap ? value.get(key) : value[key]) {
                const item$ = isMap ? each.get(key) : each[key];
                const props = {
                    key,
                    id: key,
                    item$,
                    item: item$,
                };
                out.push(require$$0.createElement(item, itemProps ? Object.assign(props, itemProps) : props));
            }
        }
    }
    return out;
}

const Memo = require$$0.memo(Computed, () => true);

const ReactiveFns = new Map();
const ReactiveFnBinders = new Map();
const Reactive = new Proxy({}, {
    get(target, p) {
        if (!target[p]) {
            const Component = ReactiveFns.get(p) || p;
            // Create a wrapper around createElement with the string so we can proxy it
            // eslint-disable-next-line react/display-name
            const render = require$$0.forwardRef((props, ref) => {
                const propsOut = { ...props };
                if (ref && (state.isFunction(ref) || !state.isEmpty(ref))) {
                    propsOut.ref = ref;
                }
                return require$$0.createElement(Component, propsOut);
            });
            target[p] = reactive(render, ReactiveFnBinders.get(p));
        }
        return target[p];
    },
});
function configureReactive({ components, binders, }) {
    if (components) {
        for (const key in components) {
            ReactiveFns.set(key, components[key]);
        }
    }
    if (binders) {
        for (const key in binders) {
            ReactiveFnBinders.set(key, binders[key]);
        }
    }
}

function Show({ if: if_, ifReady, else: else_, wrap, children }) {
    const value = useSelector(if_ !== null && if_ !== void 0 ? if_ : ifReady);
    const show = ifReady !== undefined ? state.isObservableValueReady(value) : value;
    const child = useSelector(show ? (state.isFunction(children) ? () => children(value) : children) : else_ !== null && else_ !== void 0 ? else_ : null, { skipCheck: true });
    return wrap ? require$$0.createElement(wrap, undefined, child) : child;
}

function Switch({ value, children, }) {
    var _a, _b, _c, _d, _e, _f;
    // Select from an object of cases
    return ((_f = (_c = (_b = (_a = children)[useSelector(value)]) === null || _b === void 0 ? void 0 : _b.call(_a)) !== null && _c !== void 0 ? _c : (_e = (_d = children)['default']) === null || _e === void 0 ? void 0 : _e.call(_d)) !== null && _f !== void 0 ? _f : null);
}

function useComputed(compute, set, deps) {
    if (!deps && state.isArray(set)) {
        deps = set;
        set = undefined;
    }
    const ref = require$$0.useRef({});
    ref.current.compute = compute;
    ref.current.set = set;
    return require$$0.useMemo(() => state.computed(() => (state.isFunction(ref.current.compute) ? ref.current.compute() : ref.current.compute), (set ? (value) => ref.current.set(value) : undefined)), deps || []);
}

const useEffectOnce = (effect) => {
    if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') {
        const refDispose = require$$0.useRef({ num: 0 });
        require$$0.useEffect(() => {
            var _a;
            // This is a hack to work around StrictMode running effects twice.
            // On the first run it returns a cleanup function that queues the dispose function
            // in a microtask. This way it will run at the end of the frame after StrictMode's second
            // run of the effect. If it's run a second time then the microtasked dispose will do nothing,
            // but the effect will return the dispose again so that when it actually unmounts it will dispose.
            // If not in StrictMode, then the dispose function will run in the microtask.
            // It's possible that this is not safe in 100% of cases, but I'm not sure what the
            // dangerous cases would be. The side effect is that the listener is still active
            // until the end of the frame, but that's probably not a problem.
            const { current } = refDispose;
            current.num++;
            const dispose = () => {
                if (current.dispose && current.num < 2) {
                    current.dispose();
                    current.dispose = undefined;
                }
                current.num--;
            };
            if (current.dispose === undefined) {
                const ret = (_a = effect()) !== null && _a !== void 0 ? _a : null;
                // If ret is a function, then it's a dispose function.
                if (ret && state.isFunction(ret)) {
                    current.dispose = ret;
                    return () => queueMicrotask(dispose);
                }
            }
            else {
                return dispose;
            }
        }, []);
    }
    else {
        require$$0.useEffect(effect, []);
    }
};

/**
 * A React hook that creates a new observable
 *
 * @param initialValue The initial value of the observable or a function that returns the initial value
 *
 * @see https://legendapp.com/open-source/state/react/react-api/#useobservable
 */
function useObservable(initialValue) {
    // Create the observable from the default value
    return require$$0.useMemo(() => state.observable((state.isFunction(initialValue) ? initialValue() : initialValue)), []);
}

function useIsMounted() {
    const obs = useObservable(false);
    const { set } = obs;
    useEffectOnce(() => {
        set(true);
        return () => set(false);
    });
    return obs;
}

function isPromise(obj) {
    return obj instanceof Promise;
}

function useMount(fn) {
    return require$$0.useEffect(() => {
        const ret = fn();
        // Allow the function to be async but if so ignore its return value
        if (!isPromise(ret)) {
            return ret;
        }
    }, []);
}
const useMountOnce = useEffectOnce;

function useObservableReducer(reducer, initializerArg, initializer) {
    const obs = useObservable(() => initializerArg !== undefined && state.isFunction(initializerArg) ? initializer(initializerArg) : initializerArg);
    const dispatch = (action) => {
        obs.set(reducer(obs.get(), action));
    };
    return [obs, dispatch];
}

function useUnmount(fn) {
    return require$$0.useEffect(() => fn, []);
}
function useUnmountOnce(fn) {
    return useEffectOnce(() => fn);
}

function useObserve(selector, reactionOrOptions, options) {
    let reaction;
    if (state.isFunction(reactionOrOptions)) {
        reaction = reactionOrOptions;
    }
    else {
        options = reactionOrOptions;
    }
    const ref = require$$0.useRef({});
    ref.current.selector = selector;
    ref.current.reaction = reaction;
    if (!ref.current.dispose) {
        ref.current.dispose = state.observe(((e) => state.computeSelector(ref.current.selector, e)), (e) => { var _a, _b; return (_b = (_a = ref.current).reaction) === null || _b === void 0 ? void 0 : _b.call(_a, e); }, options);
    }
    useUnmountOnce(() => {
        var _a, _b;
        (_b = (_a = ref.current) === null || _a === void 0 ? void 0 : _a.dispose) === null || _b === void 0 ? void 0 : _b.call(_a);
    });
    return ref.current.dispose;
}

function useObserveEffect(selector, reactionOrOptions, options) {
    let reaction;
    if (state.isFunction(reactionOrOptions)) {
        reaction = reactionOrOptions;
    }
    else {
        options = reactionOrOptions;
    }
    const ref = require$$0.useRef({ selector });
    ref.current = { selector, reaction };
    useEffectOnce(() => state.observe(((e) => {
        const { selector } = ref.current;
        return state.isFunction(selector) ? selector(e) : selector;
    }), (e) => { var _a, _b; return (_b = (_a = ref.current).reaction) === null || _b === void 0 ? void 0 : _b.call(_a, e); }, options));
}

function useWhen(predicate, effect) {
    return require$$0.useMemo(() => state.when(predicate, effect), []);
}
function useWhenReady(predicate, effect) {
    return require$$0.useMemo(() => state.whenReady(predicate, effect), []);
}

exports.Computed = Computed;
exports.For = For;
exports.Memo = Memo;
exports.Reactive = Reactive;
exports.Show = Show;
exports.Switch = Switch;
exports.configureReactive = configureReactive;
exports.hasSymbol = hasSymbol;
exports.observer = observer;
exports.reactive = reactive;
exports.reactiveComponents = reactiveComponents;
exports.reactiveObserver = reactiveObserver;
exports.useComputed = useComputed;
exports.useEffectOnce = useEffectOnce;
exports.useIsMounted = useIsMounted;
exports.useMount = useMount;
exports.useMountOnce = useMountOnce;
exports.useObservable = useObservable;
exports.useObservableReducer = useObservableReducer;
exports.useObserve = useObserve;
exports.useObserveEffect = useObserveEffect;
exports.usePauseProvider = usePauseProvider;
exports.useSelector = useSelector;
exports.useUnmount = useUnmount;
exports.useUnmountOnce = useUnmountOnce;
exports.useWhen = useWhen;
exports.useWhenReady = useWhenReady;
//# sourceMappingURL=react.js.map
