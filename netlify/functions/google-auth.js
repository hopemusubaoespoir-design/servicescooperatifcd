"use strict";

const { createHmac, randomBytes, timingSafeEqual } = require("node:crypto");

const SESSION_COOKIE = "coop_session";
const STATE_COOKIE = "google_oauth_state";
const SESSION_MAX_AGE = 7 * 24 * 60 * 60;
const STATE_MAX_AGE = 10 * 60;
const FUNCTION_PATH = "/.netlify/functions/google-auth";

function getConfig() {
    const siteValue = process.env.SITE_URL || process.env.URL;
    let siteUrl = null;
    try {
        if (siteValue) {
            const parsed = new URL(siteValue);
            const localHost = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
            if (parsed.protocol === "https:" || (localHost && parsed.protocol === "http:")) siteUrl = parsed.origin;
        }
    } catch (error) {
        siteUrl = null;
    }
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const sessionSecret = process.env.SESSION_SECRET;
    if (!siteUrl || !clientId || !clientSecret || !sessionSecret || sessionSecret.length < 32) return null;
    return { siteUrl, clientId, clientSecret, sessionSecret };
}

function baseHeaders(contentType) {
    const headers = {
        "Cache-Control": "no-store, max-age=0",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff"
    };
    if (contentType) headers["Content-Type"] = contentType;
    return headers;
}

function jsonResponse(statusCode, payload, cookies) {
    const result = { statusCode, headers: baseHeaders("application/json; charset=utf-8"), body: JSON.stringify(payload) };
    if (cookies && cookies.length) result.multiValueHeaders = { "Set-Cookie": cookies };
    return result;
}

function redirectResponse(siteUrl, result, cookies) {
    const target = new URL("/", siteUrl);
    target.searchParams.set("google_auth", result);
    const response = { statusCode: 302, headers: { ...baseHeaders(), Location: target.toString() }, body: "" };
    if (cookies && cookies.length) response.multiValueHeaders = { "Set-Cookie": cookies };
    return response;
}

function cookieOptions(siteUrl, maxAge) {
    const secure = new URL(siteUrl).protocol === "https:" ? "; Secure" : "";
    return "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + maxAge + secure;
}

function readCookie(event, name) {
    const headers = event.headers || {};
    const raw = headers.cookie || headers.Cookie || "";
    for (const part of raw.split(";")) {
        const separator = part.indexOf("=");
        if (separator < 0) continue;
        const key = part.slice(0, separator).trim();
        if (key !== name) continue;
        const value = part.slice(separator + 1).trim();
        try { return decodeURIComponent(value); } catch (error) { return value; }
    }
    return "";
}

function safeEqual(left, right) {
    const a = Buffer.from(String(left));
    const b = Buffer.from(String(right));
    return a.length === b.length && timingSafeEqual(a, b);
}

function sign(value, secret) {
    return createHmac("sha256", secret).update(value).digest("base64url");
}

function makeSessionCookie(user, config) {
    const payload = Buffer.from(JSON.stringify({
        sub: user.sub,
        email: user.email,
        name: user.name || user.email,
        exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE
    })).toString("base64url");
    const value = payload + "." + sign(payload, config.sessionSecret);
    return SESSION_COOKIE + "=" + value + cookieOptions(config.siteUrl, SESSION_MAX_AGE);
}

function getSession(event, config) {
    const value = readCookie(event, SESSION_COOKIE);
    const separator = value.lastIndexOf(".");
    if (separator <= 0) return null;
    const payload = value.slice(0, separator);
    const signature = value.slice(separator + 1);
    if (!safeEqual(signature, sign(payload, config.sessionSecret))) return null;
    try {
        const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
        if (!session.sub || !session.email || !Number.isFinite(session.exp) || session.exp <= Math.floor(Date.now() / 1000)) return null;
        return { sub: session.sub, email: session.email, name: session.name || session.email };
    } catch (error) {
        return null;
    }
}

function clearCookie(name, siteUrl) {
    return name + "=" + cookieOptions(siteUrl, 0);
}

function cookieSecureFromEnvironment() {
    const configuredUrl = process.env.SITE_URL || process.env.URL || "https://localhost";
    try { return new URL(configuredUrl).protocol === "https:"; } catch (error) { return true; }
}

function clearCookieWithoutSite(name) {
    return name + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" + (cookieSecureFromEnvironment() ? "; Secure" : "");
}

async function handleCallback(event, config, query) {
    const clearState = clearCookie(STATE_COOKIE, config.siteUrl);
    if (query.error) return redirectResponse(config.siteUrl, "cancelled", [clearState]);
    const stateCookie = readCookie(event, STATE_COOKIE);
    if (!query.code || !query.state || !stateCookie || !safeEqual(query.state, stateCookie)) {
        return redirectResponse(config.siteUrl, "failed", [clearState]);
    }

    try {
        const redirectUri = new URL(FUNCTION_PATH + "?action=callback", config.siteUrl).toString();
        const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                code: query.code,
                client_id: config.clientId,
                client_secret: config.clientSecret,
                redirect_uri: redirectUri,
                grant_type: "authorization_code"
            })
        });
        if (!tokenResponse.ok) throw new Error("Google token exchange failed");
        const tokens = await tokenResponse.json();
        if (!tokens.access_token) throw new Error("Google did not return an access token");

        const profileResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
            headers: { Authorization: "Bearer " + tokens.access_token }
        });
        if (!profileResponse.ok) throw new Error("Google profile verification failed");
        const profile = await profileResponse.json();
        if (!profile.sub || !profile.email || !(profile.email_verified === true || profile.email_verified === "true")) {
            throw new Error("Google account is missing a verified email");
        }
        return redirectResponse(config.siteUrl, "success", [clearState, makeSessionCookie(profile, config)]);
    } catch (error) {
        console.error("Google OAuth callback failed:", error && error.name ? error.name : "Error");
        return redirectResponse(config.siteUrl, "failed", [clearState]);
    }
}

exports.handler = async function (event) {
    const method = event.httpMethod || "GET";
    const query = event.queryStringParameters || {};
    const action = query.action || "me";

    if (action === "logout") {
        if (method !== "POST") return jsonResponse(405, { error: "Method not allowed" });
        return jsonResponse(200, { authenticated: false }, [clearCookieWithoutSite(SESSION_COOKIE)]);
    }

    const config = getConfig();
    if (action === "me") {
        const user = config ? getSession(event, config) : null;
        return jsonResponse(200, { configured: Boolean(config), authenticated: Boolean(user), user });
    }
    if (method !== "GET") return jsonResponse(405, { error: "Method not allowed" });
    if (!config) return jsonResponse(503, { error: "Google authentication is not configured." });

    if (action === "login") {
        const state = randomBytes(32).toString("base64url");
        const authorizationUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
        authorizationUrl.search = new URLSearchParams({
            client_id: config.clientId,
            redirect_uri: new URL(FUNCTION_PATH + "?action=callback", config.siteUrl).toString(),
            response_type: "code",
            scope: "openid email profile",
            state,
            prompt: "select_account"
        }).toString();
        return {
            statusCode: 302,
            headers: { ...baseHeaders(), Location: authorizationUrl.toString() },
            multiValueHeaders: { "Set-Cookie": [STATE_COOKIE + "=" + state + cookieOptions(config.siteUrl, STATE_MAX_AGE)] },
            body: ""
        };
    }
    if (action === "callback") return handleCallback(event, config, query);
    return jsonResponse(404, { error: "Not found" });
};
