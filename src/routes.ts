import { Request, Response, Router } from "express";
import { prisma } from "./prisma.js";

const router = Router();

router.get("/status", async (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

router.get("/config", async (_req, res) => {
  res.json({
    ssid: process.env.ESP_WIFI_SSID ?? null,
    password: process.env.ESP_WIFI_PASSWORD ?? null,
    apiBaseUrl: process.env.APP_BASE_URL ?? null
  });
});

router.get("/cards", async (_req, res) => {
  const cards = await prisma.user.findMany({ select: { cardNum: true } });
  res.json(cards.map((item: { cardNum: string }) => item.cardNum));
});

router.post("/cards", async (req, res) => {
  const cardNum = req.body.cardNum || req.query.cardNum;
  if (!cardNum || typeof cardNum !== "string") {
    return res.status(400).json({ error: "cardNum is required" });
  }
  try {
    const user = await prisma.user.create({ data: { cardNum } });
    return res.status(201).json(user);
  } catch (error) {
    return res.status(400).json({ error: "Unable to create card", detail: error });
  }
});

router.get("/door-state", async (_req, res) => {
  const latest = await prisma.doorState.findFirst({ orderBy: { createdAt: "desc" } });
  res.json({ state: latest?.state ?? "OFF" });
});

async function saveDoorState(req: Request, res: Response) {
  const state = req.body.state || req.query.state;
  if (!state || (state !== "ON" && state !== "OFF")) {
    return res.status(400).json({ error: "state must be ON or OFF" });
  }
  const doorState = await prisma.doorState.upsert({
    where: { id: 1 },
    update: { state },
    create: { id: 1, state }
  });
  res.json(doorState);
}

router.post("/door-state", saveDoorState);
router.put("/door-state", saveDoorState);

async function saveTempHumiRecord(req: Request, res: Response) {
  const temperature = Number(req.body.temperature ?? req.query.temperature);
  const humidity = Number(req.body.humidity ?? req.query.humidity);

  if (Number.isNaN(temperature) || Number.isNaN(humidity)) {
    return res.status(400).json({ error: "temperature and humidity are required" });
  }

  const record = await prisma.tempHumi.create({ data: { temperature, humidity } });
  const totalCount = await prisma.tempHumi.count();

  if (totalCount > 25) {
    const excess = totalCount - 25;
    const oldest = await prisma.tempHumi.findMany({
      orderBy: { id: "asc" },
      take: excess,
      select: { id: true }
    });
    await prisma.tempHumi.deleteMany({
      where: { id: { in: oldest.map((row: { id: number }) => row.id) } }
    });
  }

  res.json(record);
}

router.get("/temp-humi", saveTempHumiRecord);
router.post("/temp-humi", saveTempHumiRecord);

router.get("/temp-humi/latest", async (_req, res) => {
  const latest = await prisma.tempHumi.findFirst({ orderBy: { updatedTime: "desc" } });
  res.json(latest);
});

router.get("/temp-humi/history", async (req, res) => {
  const limit = Number(req.query.limit ?? 30);
  const data = await prisma.tempHumi.findMany({
    orderBy: { updatedTime: "desc" },
    take: limit
  });
  res.json(data.reverse());
});

router.post("/temp-humi", async (req, res) => {
  const temperature = Number(req.body.temperature ?? req.query.temperature);
  const humidity = Number(req.body.humidity ?? req.query.humidity);

  if (Number.isNaN(temperature) || Number.isNaN(humidity)) {
    return res.status(400).json({ error: "temperature and humidity are required" });
  }

  const record = await prisma.tempHumi.create({ data: { temperature, humidity } });
  res.json(record);
});

export const apiRouter = router;
