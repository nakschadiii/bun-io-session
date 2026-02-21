import { type JWTPayload } from "jose";
import { type Observable } from "@legendapp/state";
import { type Socket } from "socket.io";
import type { LogLevel, LogOptions } from "../logger";

export type SocketSession = {
    client: string | null;
    refresh: (callback?: Function) => Promise<void>;
    users: Observable<{ id: string, createdAt: number }[]>;
    currentUser: Observable<string | null>;
    validateJwt: (token: string) => Promise<JWTPayload>;
    createJwt: (data: any) => Promise<string>;
}

export type InjectedSocket = Socket & { session?: SocketSession };

export interface ClientIdentityServiceProps {
    createLogger?: ({ service, scope }: LogOptions) => (level: LogLevel, message: string, ...args: unknown[]) => void;
    clientIdCookieName?: string;
    jwtSecret?: string;
    createAndReturnClientID?: (visitorId: string) => Promise<string | null>;
    findClient?: ({ clientId, visitorId }: { clientId?: string; visitorId?: string; }) => Promise<any>;
    getSessions?: (client: string) => Promise<{
        user: string;
        createdAt: number;
    }[]>;
    onUsersChange?: (socket: Socket, data: {
        users: {
            jwt: string;
            createdAt: number;
        }[];
        currentUser: {
            jwt: string;
        };
    }) => void;
    engine: any;
}

