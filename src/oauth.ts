import type { Request, Response } from "express";
import { Router } from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { prisma } from "./prisma.js";
import { issueTokens } from "./adminAuth.js";

type OAuthProvider = "google" | "github";

type StatePayload = {
  provider: OAuthProvider;
  nonce: string;
};

function getJwtSecret() {
  const secret = process.env.JWT_SECRET?.trim();
  return secret && secret.length >= 32 ? secret : null;
}

function getFrontendUrl() {
  const raw = (process.env.FRONTEND_URL || "").split(",")[0]?.trim();
  return raw ? raw.replace(/\/$/, "") : null;
}

function getRedirectBase(req: Request) {
  const base = (process.env.APP_BASE_URL || "").trim().replace(/\/$/, "");
  if (base) return base;
  const host = req.get("host");
  return `${req.protocol}://${host}`;
}

function frontendCallback(params: Record<string, string>) {
  const frontend = getFrontendUrl();
  const target = frontend ? `${frontend}/auth/callback` : "/";
  const fragment = new URLSearchParams(params).toString();
  return `${target}#${fragment}`;
}

function signState(payload: StatePayload) {
  const secret = getJwtSecret();
  if (!secret) throw new Error("JWT_SECRET not configured");
  return jwt.sign(payload, secret, { expiresIn: "10m" });
}

function verifyState(token: string): StatePayload {
  const secret = getJwtSecret();
  if (!secret) throw new Error("JWT_SECRET not configured");
  return jwt.verify(token, secret) as StatePayload;
}

async function buildUniqueUsername(seed: string) {
  const cleaned = (seed || "user").toLowerCase().replace(/[^a-z0-9_.-]+/g, "").slice(0, 40) || "user";
  let candidate = cleaned;
  let suffix = 0;
  while (true) {
    const existing = await prisma.admin.findUnique({ where: { username: candidate } });
    if (!existing) return candidate;
    suffix += 1;
    candidate = `${cleaned}${suffix}`;
    if (candidate.length > 60) candidate = candidate.slice(0, 60);
    if (suffix > 1000) {
      return `${cleaned}_${crypto.randomBytes(4).toString("hex")}`;
    }
  }
}

async function findOrCreateAdminFromOAuth(
  provider: OAuthProvider,
  providerSubject: string,
  email: string | null,
  displayName: string
) {
  const linked = await prisma.adminIdentity.findUnique({
    where: { provider_providerSubject: { provider, providerSubject } },
    include: { admin: { select: { id: true, tokenVersion: true } } }
  });
  if (linked) return linked.admin;

  if (email) {
    const existingByEmail = await prisma.admin.findUnique({
      where: { email },
      select: { id: true, tokenVersion: true }
    });
    if (existingByEmail) {
      await prisma.adminIdentity.create({
        data: { adminId: existingByEmail.id, provider, providerSubject, email }
      });
      return existingByEmail;
    }
  }

  const usernameSeed = email ? email.split("@")[0] : displayName || `${provider}_${providerSubject}`;
  const username = await buildUniqueUsername(usernameSeed);

  const created = await prisma.admin.create({
    data: {
      username,
      email,
      identities: { create: { provider, providerSubject, email } }
    },
    select: { id: true, tokenVersion: true }
  });
  return created;
}

export const oauthRouter = Router();

oauthRouter.get("/google", (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID?.trim();
  const secret = getJwtSecret();
  if (!clientId || !secret) {
    return res.redirect(frontendCallback({ error: "google_not_configured" }));
  }
  const state = signState({ provider: "google", nonce: crypto.randomBytes(16).toString("base64url") });
  const redirectUri = `${getRedirectBase(req)}/api/auth/google/callback`;
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", state);
  url.searchParams.set("access_type", "online");
  url.searchParams.set("prompt", "select_account");
  res.redirect(url.toString());
});

oauthRouter.get("/google/callback", async (req: Request, res: Response) => {
  try {
    const code = String(req.query.code || "");
    const state = String(req.query.state || "");
    if (!code || !state) throw new Error("missing code/state");
    const decoded = verifyState(state);
    if (decoded.provider !== "google") throw new Error("invalid state");

    const redirectUri = `${getRedirectBase(req)}/api/auth/google/callback`;
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID!,
        client_secret: process.env.GOOGLE_CLIENT_SECRET!,
        code,
        grant_type: "authorization_code",
        redirect_uri: redirectUri
      })
    });
    if (!tokenRes.ok) throw new Error("token exchange failed");
    const tokenJson = (await tokenRes.json()) as { access_token?: string };
    const accessToken = tokenJson.access_token;
    if (!accessToken) throw new Error("no access_token");

    const userRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!userRes.ok) throw new Error("userinfo failed");
    const profile = (await userRes.json()) as {
      sub: string;
      email?: string;
      name?: string;
    };
    const subject = String(profile.sub);
    const email = profile.email?.toLowerCase() || null;
    const name = profile.name || profile.email || `google_${subject}`;

    const admin = await findOrCreateAdminFromOAuth("google", subject, email, name);
    const tokens = await issueTokens(admin, req);
    return res.redirect(
      frontendCallback({
        provider: "google",
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken
      })
    );
  } catch (err) {
    return res.redirect(frontendCallback({ error: "google_oauth_failed" }));
  }
});

oauthRouter.get("/github", (req, res) => {
  const clientId = process.env.GITHUB_CLIENT_ID?.trim();
  const secret = getJwtSecret();
  if (!clientId || !secret) {
    return res.redirect(frontendCallback({ error: "github_not_configured" }));
  }
  const state = signState({ provider: "github", nonce: crypto.randomBytes(16).toString("base64url") });
  const redirectUri = `${getRedirectBase(req)}/api/auth/github/callback`;
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", "read:user user:email");
  url.searchParams.set("state", state);
  url.searchParams.set("allow_signup", "true");
  res.redirect(url.toString());
});

oauthRouter.get("/github/callback", async (req: Request, res: Response) => {
  try {
    const code = String(req.query.code || "");
    const state = String(req.query.state || "");
    if (!code || !state) throw new Error("missing code/state");
    const decoded = verifyState(state);
    if (decoded.provider !== "github") throw new Error("invalid state");

    const redirectUri = `${getRedirectBase(req)}/api/auth/github/callback`;
    const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        client_id: process.env.GITHUB_CLIENT_ID!,
        client_secret: process.env.GITHUB_CLIENT_SECRET!,
        code,
        redirect_uri: redirectUri
      })
    });
    if (!tokenRes.ok) throw new Error("token exchange failed");
    const tokenJson = (await tokenRes.json()) as { access_token?: string };
    const accessToken = tokenJson.access_token;
    if (!accessToken) throw new Error("no access_token");

    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "smart-farm-backend"
      }
    });
    if (!userRes.ok) throw new Error("user fetch failed");
    const profile = (await userRes.json()) as {
      id: number;
      login: string;
      name?: string;
      email?: string | null;
    };
    let email = profile.email?.toLowerCase() || null;

    if (!email) {
      const emailRes = await fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "smart-farm-backend"
        }
      });
      if (emailRes.ok) {
        const emails = (await emailRes.json()) as Array<{ email: string; primary: boolean; verified: boolean }>;
        const primary = emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified) || emails[0];
        if (primary) email = primary.email.toLowerCase();
      }
    }

    const subject = String(profile.id);
    const name = profile.name || profile.login || `github_${subject}`;

    const admin = await findOrCreateAdminFromOAuth("github", subject, email, name);
    const tokens = await issueTokens(admin, req);
    return res.redirect(
      frontendCallback({
        provider: "github",
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken
      })
    );
  } catch (err) {
    return res.redirect(frontendCallback({ error: "github_oauth_failed" }));
  }
});
