import { Observable } from '@legendapp/state';
/**
 * A React hook that creates a new observable
 *
 * @param initialValue The initial value of the observable or a function that returns the initial value
 *
 * @see https://legendapp.com/open-source/state/react/react-api/#useobservable
 */
export declare function useObservable<T>(initialValue?: T | (() => T) | (() => Promise<T>)): Observable<T>;
