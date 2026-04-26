import type { Request, Response, NextFunction } from "express";
import { Router } from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import { prisma } from "./prisma.js";

type AccessTokenPayload = {
  sub: string; // admin id
  sid: string; // admin session id
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
  const refreshTtlSeconds = parseDurationSeconds(process.env.JWT_REFRESH_TTL, 14 * 24 * 60 * 60);

  const ip = req.ip || null;
  const userAgent = req.get("user-agent") || null;

  const refreshToken = randomToken();
  const refreshTokenHash = sha256Base64Url(refreshToken);
  const expiresAt = new Date(Date.now() + refreshTtlSeconds * 1000);
  const session = await prisma.adminSession.create({
    data: {
      adminId: admin.id,
      refreshTokenHash,
      adminTokenVersion: admin.tokenVersion,
      expiresAt,
      ip,
      userAgent
    },
    select: { id: true }
  });

  const accessToken = jwt.sign(
    {
      sub: String(admin.id),
      sid: session.id,
      typ: "admin_access",
      ver: admin.tokenVersion
    } satisfies Omit<AccessTokenPayload, "iat" | "exp">,
    jwtSecret,
    { expiresIn: accessTtlSeconds }
  );

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
    if (!decoded.sid) {
      return res.status(401).json({ error: "Missing session id" });
    }

    const session = await prisma.adminSession.findUnique({
      where: { id: decoded.sid },
      include: { admin: { select: { id: true, tokenVersion: true } } }
    });
    if (!session || session.revokedAt || session.expiresAt <= new Date()) {
      return res.status(401).json({ error: "Session revoked or expired" });
    }
    if (session.adminId !== adminId) {
      return res.status(401).json({ error: "Invalid token session" });
    }
    if (session.admin.tokenVersion !== decoded.ver || session.adminTokenVersion !== decoded.ver) {
      return res.status(401).json({ error: "Token revoked" });
    }

    res.locals.adminId = session.admin.id;
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
