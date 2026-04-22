import express from "express";
import cors from "cors";
import { apiRouter } from "./routes.js";

const app = express();
const port = Number(process.env.PORT || process.env.SERVER_PORT || 4000);
const host = process.env.HOST || "127.0.0.1";

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map((origin) => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.length === 0) return callback(null, true);
      const normalized = origin.replace(/\/$/, "");
      if (allowedOrigins.includes(normalized)) return callback(null, true);
      return callback(new Error("Origin not allowed"));
    },
    credentials: true
  })
);
app.use(express.json());
app.use("/api", apiRouter);

app.get("/", (_req, res) => {
  res.send({ message: "Smart Farm Express API is running" });
});

app.listen(port, host, () => {
  console.log(`Server listening on http://${host}:${port}`);
});
