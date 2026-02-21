import type { Change, ObservablePersistLocal, PersistMetadata, PersistOptionsLocal } from '@legendapp/state';
export declare class ObservablePersistMMKV implements ObservablePersistLocal {
    private data;
    private storages;
    getTable<T = any>(table: string, config: PersistOptionsLocal, init: object): T;
    getMetadata(table: string, config: PersistOptionsLocal): PersistMetadata;
    set(table: string, changes: Change[], config: PersistOptionsLocal): void;
    setMetadata(table: string, metadata: PersistMetadata, config: PersistOptionsLocal): Promise<void>;
    deleteTable(table: string, config: PersistOptionsLocal): void;
    deleteMetadata(table: string, config: PersistOptionsLocal): void;
    private getStorage;
    private setValue;
    private save;
}
