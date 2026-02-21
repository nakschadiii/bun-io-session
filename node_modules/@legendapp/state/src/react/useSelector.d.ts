import { Selector } from '@legendapp/state';
import type { UseSelectorOptions } from './reactInterfaces';
export declare function useSelector<T>(selector: Selector<T>, options?: UseSelectorOptions): T;
