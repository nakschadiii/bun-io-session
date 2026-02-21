import { SignJWT, jwtVerify } from "jose";

export const secret = new TextEncoder().encode(process.env.COOKIE_SECRET);

export async function sign(payload, issuer, audience) {
    return new SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setIssuer(issuer)
        .setAudience(audience)
        .setExpirationTime('7d')
        .sign(secret);
}

export async function verify(token, issuer, audience) {
    const { payload } = await jwtVerify(token, secret, {
        issuer,
        audience,
    });

    return payload;
}