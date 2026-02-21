import { Hono } from "hono";
import { deleteCookie, getSignedCookie, setSignedCookie } from "hono/cookie";
import { v4 as uuidv4 } from 'uuid';
import * as JosePayload from './payload';

export const cookiesApp = new Hono();

export const JWT_WHITELIST = {
    'hola-server': [
        'hola-client',
        'hola-admin',
    ],
    'auth-server': [
        'web-client',
        'mobile-client',
    ],
} as const;

export function validateJwtContext(issuer?: string, audience?: string) {
    if (!issuer || !audience) {
        throw new Error('Missing issuer or audience');
    }

    const allowedAudiences = JWT_WHITELIST[issuer as keyof typeof JWT_WHITELIST];
    if (!allowedAudiences) {
        throw new Error('Issuer not allowed');
    }

    if (!allowedAudiences.includes(audience as any)) {
        throw new Error('Audience not allowed');
    }

    return { issuer, audience };
}

function getJwtContext(c: any) {
    const issuer = c.req.header('x-issuer');
    const audience = c.req.header('x-audience');

    if (!issuer || !audience) {
        throw new Error('Missing issuer or audience');
    }

    return validateJwtContext(issuer, audience);
}

let testNull = false;
/* setTimeout(() => {
    testNull = !testNull;
    console.log("testNull", testNull);
}, 5000); */

cookiesApp.get('/', async (c) => {
    const name = c.req.param('name');

    let issuer, audience;
    try {
        ({ issuer, audience } = getJwtContext(c));
    } catch {
        return c.json({ error: 'Missing issuer or audience' }, 400);
    }

    const token = await getSignedCookie(c, process.env.COOKIE_SECRET!, name!);
    if (!token) return c.json({ error: 'Cookie invalid or missing' }, 401);

    try {
        const payload = await JosePayload.verify(token, issuer, audience);
        return c.json({ name, value: testNull ? null : payload.value });
    } catch {
        deleteCookie(c, name!, { path: '/' });
        return c.json({ error: 'JWT expired or invalid' }, 401);
    }
});

cookiesApp.post('/', async (c) => {
    const name = c.req.param('name');
    const value = uuidv4();

    let issuer, audience;
    try {
        ({ issuer, audience } = getJwtContext(c));
    } catch {
        return c.json({ error: 'Missing issuer or audience' }, 400);
    }

    const token = await JosePayload.sign({ value }, issuer, audience);
    
    try {
        await setSignedCookie(
            c,
            name,
            token,
            process.env.COOKIE_SECRET!,
            {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                path: '/',

                expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30 * 3),
            }
        );

        return c.json({ name, value });
    } catch (error) {
        console.error(error);
        return c.json({ error: 'Failed to set cookie' }, 500);
    }
});
