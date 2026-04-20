import express from "express";
import cors from "cors";
import { apiRouter } from "./routes.js";

const app = express();
const port = Number(process.env.PORT || process.env.SERVER_PORT || 4000);
const host = process.env.HOST || "127.0.0.1";

app.use(cors());
app.use(express.json());
app.use("/api", apiRouter);

app.get("/", (_req, res) => {
  res.send({ message: "Smart Farm Express API is running" });
});

app.listen(port, host, () => {
  console.log(`Server listening on http://${host}:${port}`);
});
