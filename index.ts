import cookie from "cookie";
import { SignJWT, jwtVerify } from "jose";
import { observable } from "@legendapp/state";
import EventEmitter from "eventemitter3";
import type { ClientIdentityServiceProps, InjectedSocket, SocketSession } from "./types";

export default function createClientIdentityService(props: ClientIdentityServiceProps) {
    try {
        const eventEmitter = new EventEmitter();

        const {
            createLogger = () => () => { },
            clientIdCookieName,
            jwtSecret,
            createAndReturnClientID,
            findClient,
            getSessions,
            onUsersChange,
            engine,
        } = props;

        if (!clientIdCookieName) throw new Error("clientIdCookieName not set in environment variables.");
        if (!jwtSecret) throw new Error("jwtSecret not set in environment variables.");
        if (!createAndReturnClientID) throw new Error("createAndReturnClientID function must be provided.");
        if (!findClient) throw new Error("findClient function must be provided.");
        if (!getSessions) throw new Error("getSessions function must be provided.");
        //if (!onUsersChange) throw new Error("onUsersChange function must be provided.");

        const JWT_SECRET = new TextEncoder().encode(jwtSecret!);

        async function signClientIdJWT(clientId: string) {
            try {
                return await new SignJWT({ client: { id: clientId } })
                    .setProtectedHeader({ alg: "HS256" })
                    .setIssuedAt()
                    .setExpirationTime("365d")
                    .sign(JWT_SECRET);
            } catch (error) {
                console.log(clientId);
                console.error(error);
                return null
            }
        }

        async function validateClientIdJWT(token: string) {
            try {
                if (!token) throw new Error("Missing token.");
                const { payload } = await jwtVerify(token, JWT_SECRET);
                return payload?.client?.id as string;
            } catch (e) {
                console.log(e);
                console.log(token);
                console.error("Invalid token");
                return null;
            }
        }

        async function attachSession(req: any, server: any) {
            const logger = createLogger({
                service: "ClientIdentityService",
                scope: "attachSession",
            });

            try {
                logger("INFO", "validating client");

                const url = new URL(req.url);
                const visitorToken = url.searchParams.get("visitorToken");
                const visitorId = await validateClientIdJWT(visitorToken!);
                let cookies: cookie.Cookies = cookie.parse(req.headers.get("cookie") || "");
                let cookieName: string | undefined = findCryptedCookieName(cookies, clientIdCookieName!);
                let jwtToken: string | undefined | null = cookies?.[cookieName!];
                let clientId: string | null | undefined = jwtToken && await validateClientIdJWT(jwtToken!);
                const registeredClient: any = await checkRegisteration(clientId!, visitorId!);

                if (clientId && !registeredClient) {
                    logger("WARN", "client not registered, invalidating client");
                    clientId = null;
                }

                if ((!clientId || !jwtToken) && !registeredClient) {
                    logger("WARN", "client invalid or not found, creating new client");
                    cookieName = cookieName ?? Bun.password.hashSync(clientIdCookieName!, "bcrypt");

                    const client = await createAndReturnClientID(visitorId!);
                    if (!client) throw new Error("client not created in createAndReturnClientID");
                    jwtToken = await signClientIdJWT(client?.toString()!);

                    const headers = new Headers();
                    headers.append(
                        "Set-Cookie",
                        `${cookieName}=${jwtToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=31536000`
                    );

                    logger("INFO", "client created", { clientId: client });
                    setTimeout((() => {
                        return server.upgrade(req, { headers });
                    }).bind(this), 1000);
                }

                logger("INFO", "client found", { clientId, registeredClient });
                clientId ??= registeredClient;
                logger("INFO", "client validated", { clientId });
                return engine.handleRequest(req, server);
            } catch (e) {
                logger("ERROR", "error during client attachment", e);
                return engine.handleRequest(req, server);
            }
        }

        async function checkRegisteration(clientId?: string, visitorId?: string) {
            const logger = createLogger({
                service: "ClientIdentityService",
                scope: "checkRegisteration",
            });

            try {
                if (!clientId && !visitorId) throw new Error("No clientId or visitorId provided");
                if (!findClient) throw new Error("findClient function must be provided.");
                const client = await findClient({ clientId, visitorId });
                if (!client) throw new Error("Client not found");

                logger("INFO", "client found", { clientId, visitorId });
                return client;
            } catch (error) {
                logger("WARN", "client not found", { clientId, visitorId });
                return null
            }
        }

        async function injectSession(socket: InjectedSocket, next: Function) {
            const idMiddleware = Date.now() + socket.id + Math.random();
            const cookies = cookie.parse(socket.handshake.headers.cookie || "");
            const cookieName = findCryptedCookieName(cookies, clientIdCookieName!);
            const jwt = cookies[cookieName!];

            socket.session = {} as SocketSession;
            socket.session.users = observable<{ id: string, createdAt: number }[]>([]);
            socket.session.currentUser = observable<string | null>(() => {
                const sessions = socket.session?.users?.get();
                if (!sessions || sessions.length === 0) return null;
                const latest = sessions.reduce((max, u) => u.createdAt > max.createdAt ? u : max);
                return latest.id ?? null;
            });

            if (jwt) socket.session.client = await validateClientIdJWT(jwt!);
            else {
                const visitorId = await validateClientIdJWT(socket?.handshake?.query?.visitorToken! as string);
                if (visitorId) socket.session.client = await checkRegisteration(undefined, visitorId as string);
                else return next(new Error("Visitor token invalid."));
            }

            socket.join("client." + socket.session.client);

            socket.session.refresh = async function (callback?: Function) {
                socket.rooms.forEach((r) => {
                    if (r.startsWith("user.")) socket.leave(r);
                });

                if (!getSessions) return;
                const sessions = await getSessions(socket?.session?.client!);
                for (const session of sessions) socket.join("user." + session.user);

                socket?.session?.users.set(
                    sessions.map((session) => ({
                        id: session.user,
                        createdAt: session.createdAt
                    }))
                );

                if (callback) callback();
            }

            socket.session.createJwt = async function (data) {
                return new SignJWT({ ...data, client: socket?.session?.client })
                    .setProtectedHeader({ alg: "HS256" })
                    .setIssuedAt()
                    .setIssuer(idMiddleware)
                    .setExpirationTime("365d")
                    .sign(JWT_SECRET);
            }

            socket.session.validateJwt = async function (token) {
                if (!token) throw new Error("Token manquant.");
                const { payload } = await jwtVerify(token, JWT_SECRET, { issuer: idMiddleware });

                const client = socket.session?.client;
                if (!client) throw new Error("Impossible de valider : session.client absent.");
                if (payload.client !== client) throw new Error("Token utilisé depuis un autre client — rejeté.");

                return payload;
            }

            const updateUsers: (...args: any[]) => void = (id, users) => {
                if (id === idMiddleware) return;
                socket?.session?.users.set(users);
            };

            eventEmitter.on(`client.${socket.session.client}.refresh`, socket?.session?.refresh);
            eventEmitter.on(`client.${socket.session.client}.users`, updateUsers);

            const unsubscribe = socket.session.users?.onChange(async ({ value: users }) => {
                eventEmitter.emit(`client.${socket?.session?.client}.users`, idMiddleware, users);

                const mappedUsers = await Promise.all(
                    users?.map(async u => ({
                        ...u,
                        jwt: await socket?.session?.createJwt({ user: u.id }),
                        id: undefined
                    })) ?? []
                ) as { jwt: string; createdAt: number }[];

                const currentUser = (
                    mappedUsers.length > 0
                        ? mappedUsers.reduce((max, u) => u.createdAt > max.createdAt ? u : max)
                        : null
                ) as { jwt: string };

                if (onUsersChange) {
                    onUsersChange(socket, { users: mappedUsers, currentUser });
                }
            }, { initial: true, immediate: true });

            socket.session.get = function () {
                return {
                    client: socket?.session?.client,
                    users: socket?.session?.users?.get(),
                    user: socket?.session?.currentUser?.get()
                }
            }

            socket.session.refresh(function () {
                next();
            });

            socket.on("disconnect", () => {
                eventEmitter.off(`client.${socket?.session?.client}.refresh`, socket?.session?.refresh);
                eventEmitter.off(`client.${socket?.session?.client}.users`, updateUsers);
                unsubscribe();
            });
        }

        function findCryptedCookieName(
            cookies: cookie.Cookies,
            name: string
        ): string | undefined {
            const criteria = (hash: string): boolean => {
                try {
                    return Bun.password.verifySync(name, hash, "bcrypt");
                } catch (error) {
                    return false;
                }
            };

            return Object.keys(cookies).find(criteria);
        }

        return {
            signClientIdJWT,
            validateClientIdJWT,
            attachSession,
            injectSession,
            refreshSession: (client_id: string) => eventEmitter.emit(`client.${client_id}.refresh`)
        };
    } catch (error) {
        throw error;
    }
}