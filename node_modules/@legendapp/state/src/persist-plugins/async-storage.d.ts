import type { Change, ObservablePersistLocal, ObservablePersistenceConfigLocalGlobalOptions, PersistMetadata, PersistOptionsLocal } from '@legendapp/state';
export declare class ObservablePersistAsyncStorage implements ObservablePersistLocal {
    private data;
    initialize(config: ObservablePersistenceConfigLocalGlobalOptions): Promise<void>;
    loadTable(table: string): void | Promise<void>;
    getTable(table: string, config: PersistOptionsLocal, init: object): any;
    getMetadata(table: string, config: PersistOptionsLocal): PersistMetadata;
    set(table: string, changes: Change[]): Promise<void>;
    setMetadata(table: string, metadata: PersistMetadata): Promise<void>;
    deleteTable(table: string): Promise<void>;
    deleteMetadata(table: string): Promise<void>;
    private setValue;
    private save;
}
