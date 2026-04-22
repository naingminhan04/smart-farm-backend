import type { Request } from "express";
import { Router } from "express";

// Compatibility router: forwards the legacy `/api/auth/*` OAuth paths to the newer
// admin OAuth implementation under `/api/admin/oauth/*`.
//
// This keeps old deployed URLs working while the frontend uses the new admin routes.
type OAuthProvider = "google" | "github";

function providerFromPath(value: string): OAuthProvider | null {
  if (value === "google" || value === "github") return value;
  return null;
}

function redirectToAdminStart(req: Request, provider: OAuthProvider) {
  const url = new URL(`/api/admin/oauth/${provider}/start`, "http://local");
  const bootstrapToken = (req.query.bootstrapToken ?? "").toString().trim();
  if (bootstrapToken) url.searchParams.set("bootstrapToken", bootstrapToken);
  return url.pathname + url.search;
}

function redirectToAdminCallback(req: Request, provider: OAuthProvider) {
  const url = new URL(`/api/admin/oauth/${provider}/callback`, "http://local");
  for (const [key, value] of Object.entries(req.query)) {
    if (Array.isArray(value)) continue;
    if (typeof value !== "string") continue;
    url.searchParams.set(key, value);
  }
  return url.pathname + url.search;
}

export const oauthRouter = Router();

oauthRouter.get("/:provider", (req, res) => {
  const provider = providerFromPath(String(req.params.provider || ""));
  if (!provider) return res.status(404).send("Not found");
  return res.redirect(307, redirectToAdminStart(req, provider));
});

oauthRouter.get("/:provider/callback", (req, res) => {
  const provider = providerFromPath(String(req.params.provider || ""));
  if (!provider) return res.status(404).send("Not found");
  return res.redirect(307, redirectToAdminCallback(req, provider));
});
