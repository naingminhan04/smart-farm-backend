import express from "express";
import cors from "cors";
import { apiRouter } from "./routes.js";

const app = express();
const port = Number(process.env.PORT);
const host = process.env.HOST || "127.0.0.1";

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map((origin) => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Non-browser clients (ESP/CLI) often send no Origin.
    if (!origin) return callback(null, true);

    const normalized = origin.replace(/\/$/, "");

    // If no allowlist configured, allow all origins.
    if (allowedOrigins.length === 0) return callback(null, true);

    // Allow common local dev origins even if FRONTEND_URL only includes prod URLs.
    const isLocalDev = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(normalized);
    if (process.env.NODE_ENV !== "production" && isLocalDev) return callback(null, true);

    if (allowedOrigins.includes(normalized)) return callback(null, true);
    return callback(new Error("Origin not allowed"));
  },
  credentials: false,
  methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 86400,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(express.json());
app.use("/api", apiRouter);

app.get("/", (_req, res) => {
  res.send({ message: "Smart Farm Express API is running" });
});

app.listen(port, host, () => {
  console.log(`Server listening on http://${host}:${port}`);
});
