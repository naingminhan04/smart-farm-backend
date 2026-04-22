import type { Request, Response, NextFunction } from "express";
import { Router } from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import { prisma } from "./prisma.js";

type AccessTokenPayload = {
  sub: string; // admin id
  typ: "admin_access";
  ver: number; // admin tokenVersion at issuance
  iat: number;
  exp: number;
};

function parseDurationSeconds(input: string | undefined, fallbackSeconds: number) {
  if (!input) return fallbackSeconds;
  const trimmed = input.trim();

  // supports: "900", "15m", "1h", "7d"
  const asNumber = Number(trimmed);
  if (Number.isFinite(asNumber) && asNumber > 0) return Math.floor(asNumber);

  const match = /^(\d+)\s*([smhd])$/i.exec(trimmed);
  if (!match) return fallbackSeconds;
  const value = Number(match[1]);
  const unit = match[2].toLowerCase();
  const multiplier = unit === "s" ? 1 : unit === "m" ? 60 : unit === "h" ? 3600 : 86400;
  return value * multiplier;
}

function getJwtSecret() {
  const secret = process.env.JWT_SECRET?.trim();
  return secret && secret.length >= 32 ? secret : null;
}

function sha256Base64Url(input: string) {
  const digest = crypto.createHash("sha256").update(input).digest("base64url");
  return digest;
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function safeEqual(a: string, b: string) {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

type OAuthProvider = "google" | "github";

function getRequiredUrlEnv(name: string) {
  const raw = process.env[name]?.trim();
  if (!raw) return null;
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

function getFrontendOrigin() {
  const url = getRequiredUrlEnv("FRONTEND_URL");
  return url ? url.origin : null;
}

function getAppBaseUrl() {
  const url = getRequiredUrlEnv("APP_BASE_URL");
  return url ? url.toString().replace(/\/+$/, "") : null;
}

function getOAuthCallbackUrl(provider: OAuthProvider) {
  const base = getAppBaseUrl();
  if (!base) return null;
  return `${base}/api/admin/oauth/${provider}/callback`;
}

function parseAllowedEmails() {
  const raw = process.env.ADMIN_OAUTH_ALLOWED_EMAILS?.trim();
  if (!raw) return null;
  const set = new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
  return set.size ? set : null;
}

function isEmailAllowed(email: string, allowed: Set<string> | null) {
  if (!allowed) return true;
  return allowed.has(email.toLowerCase());
}

function oauthConfig(provider: OAuthProvider) {
  if (provider === "google") {
    const clientId = process.env.GOOGLE_CLIENT_ID?.trim() || "";
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET?.trim() || "";
    return clientId && clientSecret ? { clientId, clientSecret } : null;
  }
  const clientId = process.env.GITHUB_CLIENT_ID?.trim() || "";
  const clientSecret = process.env.GITHUB_CLIENT_SECRET?.trim() || "";
  return clientId && clientSecret ? { clientId, clientSecret } : null;
}

function htmlPostMessage(payload: unknown, origin: string) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body><script>
(function(){
  try {
    var msg = ${JSON.stringify(payload)};
    if (window.opener && window.opener.postMessage) {
      window.opener.postMessage(msg, ${JSON.stringify(origin)});
    }
  } catch (e) {}
  window.close();
})();
</script></body></html>`;
}

async function findOrCreateAdminUsername(base: string) {
  const normalized = base
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "")
    .slice(0, 24);
  const prefix = normalized.length >= 3 ? normalized : `admin${normalized}`;

  for (let i = 0; i < 8; i++) {
    const suffix = i === 0 ? "" : `_${crypto.randomBytes(3).toString("hex")}`;
    const username = (prefix + suffix).slice(0, 64);
    try {
      const created = await prisma.admin.create({
        data: { username },
        select: { id: true, username: true, tokenVersion: true }
      });
      return created;
    } catch {
      // retry on unique collisions
    }
  }
  throw new Error("Unable to create admin username");
}

export async function issueTokens(admin: { id: number; tokenVersion: number }, req: Request) {
  const jwtSecret = getJwtSecret();
  if (!jwtSecret) {
    throw new Error("JWT_SECRET missing or too short (min 32 chars)");
  }

  const accessTtlSeconds = parseDurationSeconds(process.env.JWT_ACCESS_TTL, 15 * 60);
  const refreshTtlSeconds = parseDurationSeconds(process.env.JWT_REFRESH_TTL, 30 * 24 * 60 * 60);

  const nowSeconds = Math.floor(Date.now() / 1000);
  const accessToken = jwt.sign(
    { sub: String(admin.id), typ: "admin_access", ver: admin.tokenVersion } satisfies Omit<
      AccessTokenPayload,
      "iat" | "exp"
    >,
    jwtSecret,
    { expiresIn: accessTtlSeconds }
  );

  const refreshToken = randomToken();
  const refreshTokenHash = sha256Base64Url(refreshToken);

  const expiresAt = new Date(Date.now() + refreshTtlSeconds * 1000);
  const ip = req.ip || null;
  const userAgent = req.get("user-agent") || null;

  await prisma.adminSession.create({
    data: {
      adminId: admin.id,
      refreshTokenHash,
      adminTokenVersion: admin.tokenVersion,
      expiresAt,
      ip,
      userAgent
    }
  });

  return { accessToken, refreshToken };
}

export async function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const jwtSecret = getJwtSecret();
  if (!jwtSecret) {
    return res.status(503).json({ error: "Admin auth is not configured" });
  }

  const auth = req.get("authorization") || "";
  const match = /^Bearer\s+(.+)$/i.exec(auth);
  if (!match) return res.status(401).json({ error: "Missing bearer token" });

  try {
    const decoded = jwt.verify(match[1], jwtSecret) as AccessTokenPayload;
    if (!decoded || decoded.typ !== "admin_access") {
      return res.status(401).json({ error: "Invalid token type" });
    }

    const adminId = Number(decoded.sub);
    if (!Number.isFinite(adminId)) {
      return res.status(401).json({ error: "Invalid token subject" });
    }

    const admin = await prisma.admin.findUnique({
      where: { id: adminId },
      select: { id: true, tokenVersion: true }
    });
    if (!admin) return res.status(401).json({ error: "Invalid token" });
    if (admin.tokenVersion !== decoded.ver) {
      return res.status(401).json({ error: "Token revoked" });
    }

    res.locals.adminId = admin.id;
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

export const adminRouter = Router();

async function registerAdmin(req: Request, res: Response) {
  const username = (req.body?.username ?? "").toString().trim();
  const password = (req.body?.password ?? "").toString();
  if (username.length < 3 || username.length > 64) {
    return res.status(400).json({ error: "username must be 3-64 chars" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "password must be at least 8 chars" });
  }

  const existing = await prisma.admin.findUnique({ where: { username } });
  if (existing) {
    return res.status(409).json({ error: "Username already taken" });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const admin = await prisma.admin.create({
    data: { username, passwordHash },
    select: { id: true, username: true, tokenVersion: true }
  });

  const tokens = await issueTokens(admin, req);
  return res.status(201).json({ admin: { id: admin.id, username: admin.username }, ...tokens });
}

adminRouter.post("/setup", loginLimiter, registerAdmin);
adminRouter.post("/register", loginLimiter, registerAdmin);

adminRouter.post("/login", loginLimiter, async (req, res) => {
  const username = (req.body?.username ?? "").toString().trim();
  const password = (req.body?.password ?? "").toString();
  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required" });
  }

  const admin = await prisma.admin.findUnique({
    where: { username },
    select: { id: true, username: true, passwordHash: true, tokenVersion: true }
  });

  // Keep error message generic to avoid user enumeration.
  if (!admin || !admin.passwordHash) return res.status(401).json({ error: "Invalid credentials" });
  const ok = await bcrypt.compare(password, admin.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const tokens = await issueTokens(admin, req);
  return res.json({ admin: { id: admin.id, username: admin.username }, ...tokens });
});

adminRouter.post("/refresh", refreshLimiter, async (req, res) => {
  const jwtSecret = getJwtSecret();
  if (!jwtSecret) {
    return res.status(503).json({ error: "Admin auth is not configured" });
  }

  const refreshToken = (req.body?.refreshToken ?? "").toString();
  if (!refreshToken) return res.status(400).json({ error: "refreshToken is required" });

  const refreshTokenHash = sha256Base64Url(refreshToken);
  const session = await prisma.adminSession.findUnique({
    where: { refreshTokenHash },
    include: { admin: { select: { id: true, username: true, tokenVersion: true } } }
  });

  if (!session || session.revokedAt || session.expiresAt <= new Date()) {
    return res.status(401).json({ error: "Invalid refresh token" });
  }
  if (session.admin.tokenVersion !== session.adminTokenVersion) {
    return res.status(401).json({ error: "Refresh token revoked" });
  }

  // Rotate refresh token on every refresh.
  await prisma.adminSession.update({
    where: { id: session.id },
    data: { revokedAt: new Date() }
  });

  const tokens = await issueTokens(
    { id: session.admin.id, tokenVersion: session.admin.tokenVersion },
    req
  );
  const accessTtlSeconds = parseDurationSeconds(process.env.JWT_ACCESS_TTL, 15 * 60);

  return res.json({
    admin: { id: session.admin.id, username: session.admin.username },
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    accessTokenExpiresInSeconds: accessTtlSeconds
  });
});

adminRouter.post("/logout", refreshLimiter, async (req, res) => {
  const refreshToken = (req.body?.refreshToken ?? "").toString();
  if (!refreshToken) return res.status(400).json({ error: "refreshToken is required" });

  const refreshTokenHash = sha256Base64Url(refreshToken);
  await prisma.adminSession.updateMany({
    where: { refreshTokenHash, revokedAt: null },
    data: { revokedAt: new Date() }
  });

  return res.status(204).send();
});

adminRouter.get("/me", requireAdmin, async (_req, res) => {
  const adminId = Number(res.locals.adminId);
  const admin = await prisma.admin.findUnique({
    where: { id: adminId },
    select: { id: true, username: true, createdAt: true }
  });
  return res.json({ admin });
});

const oauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false
});

// Returns a short-lived token used only for the first admin OAuth signup flow.
// This avoids putting ADMIN_SETUP_TOKEN in a URL.
adminRouter.post("/oauth/bootstrap-token", loginLimiter, async (req, res) => {
  const setupToken = process.env.ADMIN_SETUP_TOKEN?.trim();
  if (!setupToken) return res.status(503).json({ error: "Admin setup is not configured" });

  const providedToken = (req.body?.token ?? "").toString();
  if (!providedToken || !safeEqual(providedToken, setupToken)) {
    return res.status(401).json({ error: "Invalid setup token" });
  }

  const existing = await prisma.admin.count();
  if (existing > 0) {
    return res.status(409).json({ error: "Admin already exists" });
  }

  const bootstrapToken = crypto.randomBytes(32).toString("base64url");
  await prisma.adminBootstrapToken.create({
    data: {
      id: bootstrapToken,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    }
  });

  return res.json({ bootstrapToken, expiresInSeconds: 10 * 60 });
});

adminRouter.get("/oauth/:provider/start", oauthLimiter, async (req, res) => {
  const provider = (req.params.provider || "").toString() as OAuthProvider;
  if (provider !== "google" && provider !== "github") {
    return res.status(404).send("Not found");
  }

  const frontendOrigin = getFrontendOrigin();
  if (!frontendOrigin) return res.status(503).send("FRONTEND_URL is not configured");

  const config = oauthConfig(provider);
  const callbackUrl = getOAuthCallbackUrl(provider);
  if (!config || !callbackUrl) return res.status(503).send("OAuth is not configured");

  const bootstrapToken = (req.query.bootstrapToken ?? "").toString().trim() || null;
  if (bootstrapToken) {
    const bt = await prisma.adminBootstrapToken.findUnique({ where: { id: bootstrapToken } });
    if (!bt || bt.usedAt || bt.expiresAt <= new Date()) {
      return res.status(401).send("Invalid bootstrap token");
    }
  }

  const state = crypto.randomBytes(32).toString("base64url");
  await prisma.adminOAuthState.create({
    data: {
      id: state,
      provider,
      bootstrapToken,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    }
  });

  if (provider === "google") {
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", callbackUrl);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("state", state);
    url.searchParams.set("include_granted_scopes", "true");
    return res.redirect(url.toString());
  }

  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", callbackUrl);
  url.searchParams.set("scope", "read:user user:email");
  url.searchParams.set("state", state);
  return res.redirect(url.toString());
});

async function oauthFail(res: Response, error: string) {
  const origin = getFrontendOrigin() || "*";
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(200).send(htmlPostMessage({ type: "sf_admin_oauth_error", error }, origin));
}

async function oauthSuccess(
  res: Response,
  payload: { admin: { id: number; username: string }; accessToken: string; refreshToken: string }
) {
  const origin = getFrontendOrigin() || "*";
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(200).send(htmlPostMessage({ type: "sf_admin_oauth", ...payload }, origin));
}

async function exchangeGoogleCode(code: string, callbackUrl: string, clientId: string, clientSecret: string) {
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: callbackUrl,
      grant_type: "authorization_code"
    })
  });

  if (!tokenRes.ok) throw new Error("Google token exchange failed");
  const tokenJson = (await tokenRes.json()) as { access_token?: string };
  const accessToken = tokenJson.access_token || "";
  if (!accessToken) throw new Error("Google access token missing");

  const userinfoRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!userinfoRes.ok) throw new Error("Google userinfo failed");
  const userinfo = (await userinfoRes.json()) as {
    sub?: string;
    email?: string;
    email_verified?: boolean;
  };
  if (!userinfo.sub || !userinfo.email) throw new Error("Google account missing subject/email");
  if (userinfo.email_verified === false) throw new Error("Google email is not verified");
  return { subject: userinfo.sub, email: userinfo.email };
}

async function exchangeGithubCode(code: string, callbackUrl: string, clientId: string, clientSecret: string) {
  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: callbackUrl
    })
  });

  if (!tokenRes.ok) throw new Error("GitHub token exchange failed");
  const tokenJson = (await tokenRes.json()) as { access_token?: string };
  const accessToken = tokenJson.access_token || "";
  if (!accessToken) throw new Error("GitHub access token missing");

  const userRes = await fetch("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" }
  });
  if (!userRes.ok) throw new Error("GitHub user fetch failed");
  const user = (await userRes.json()) as { id?: number };
  if (!user.id) throw new Error("GitHub user id missing");

  const emailsRes = await fetch("https://api.github.com/user/emails", {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" }
  });
  if (!emailsRes.ok) throw new Error("GitHub emails fetch failed");
  const emails = (await emailsRes.json()) as Array<{ email: string; primary: boolean; verified: boolean }>;
  const primary = emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified);
  if (!primary?.email) throw new Error("GitHub verified email missing");

  return { subject: String(user.id), email: primary.email };
}

adminRouter.get("/oauth/:provider/callback", oauthLimiter, async (req, res) => {
  const provider = (req.params.provider || "").toString() as OAuthProvider;
  if (provider !== "google" && provider !== "github") return res.status(404).send("Not found");

  const config = oauthConfig(provider);
  const callbackUrl = getOAuthCallbackUrl(provider);
  if (!config || !callbackUrl) return oauthFail(res, "OAuth is not configured");

  const code = (req.query.code ?? "").toString();
  const state = (req.query.state ?? "").toString();
  if (!code || !state) return oauthFail(res, "Missing code/state");

  const stored = await prisma.adminOAuthState.findUnique({ where: { id: state } });
  if (!stored || stored.provider !== provider || stored.expiresAt <= new Date()) {
    return oauthFail(res, "Invalid state");
  }

  // One-time state
  await prisma.adminOAuthState.delete({ where: { id: state } });

  try {
    const allowed = parseAllowedEmails();

    const { subject, email } =
      provider === "google"
        ? await exchangeGoogleCode(code, callbackUrl, config.clientId, config.clientSecret)
        : await exchangeGithubCode(code, callbackUrl, config.clientId, config.clientSecret);

    // If allowlist is configured, enforce it.
    if (allowed && !isEmailAllowed(email, allowed)) {
      return oauthFail(res, "Email is not allowed for admin access");
    }

    const identity = await prisma.adminIdentity.findUnique({
      where: { provider_providerSubject: { provider, providerSubject: subject } },
      include: { admin: { select: { id: true, username: true, tokenVersion: true } } }
    });

    let admin = identity?.admin ?? null;

    if (!admin) {
      if (!stored.bootstrapToken) {
        return oauthFail(res, "This account is not linked to an admin");
      }

      const bt = await prisma.adminBootstrapToken.findUnique({ where: { id: stored.bootstrapToken } });
      if (!bt || bt.usedAt || bt.expiresAt <= new Date()) {
        return oauthFail(res, "Bootstrap token expired");
      }

      const existingAdmins = await prisma.admin.count();
      if (existingAdmins > 0) {
        return oauthFail(res, "Admin already exists");
      }

      // Mark bootstrap token used.
      await prisma.adminBootstrapToken.update({
        where: { id: stored.bootstrapToken },
        data: { usedAt: new Date() }
      });

      const baseUsername = email.split("@")[0] || "admin";
      const createdAdmin = await findOrCreateAdminUsername(baseUsername);

      admin = createdAdmin;

      await prisma.admin.update({
        where: { id: createdAdmin.id },
        data: { email }
      });

      await prisma.adminIdentity.create({
        data: {
          adminId: createdAdmin.id,
          provider,
          providerSubject: subject,
          email
        }
      });
    } else {
      // Update email on identity to the latest value.
      await prisma.adminIdentity.update({
        where: { provider_providerSubject: { provider, providerSubject: subject } },
        data: { email }
      });
    }

    const tokens = await issueTokens({ id: admin.id, tokenVersion: admin.tokenVersion }, req);
    return oauthSuccess(res, {
      admin: { id: admin.id, username: admin.username },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken
    });
  } catch (err) {
    return oauthFail(res, err instanceof Error ? err.message : "OAuth failed");
  }
});
