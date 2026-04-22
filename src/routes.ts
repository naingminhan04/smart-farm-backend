import { Request, Response, Router } from "express";
import { prisma } from "./prisma.js";
import { adminRouter, requireAdmin } from "./adminAuth.js";

const router = Router();

router.use("/admin", adminRouter);

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

router.post("/cards", requireAdmin, async (req, res) => {
  const cardNum = (req.body.cardNum || req.query.cardNum || "").toString().trim().toUpperCase();
  if (!cardNum) {
    return res.status(400).json({ error: "cardNum is required" });
  }
  try {
    const user = await prisma.user.create({ data: { cardNum } });
    return res.status(201).json(user);
  } catch (error) {
    return res.status(400).json({ error: "Unable to create card", detail: error });
  }
});

router.put("/cards/:cardNum", requireAdmin, async (req, res) => {
  const currentCardNum = (req.params.cardNum || "").toString().trim().toUpperCase();
  const nextCardNum = (req.body.cardNum || req.query.cardNum || "").toString().trim().toUpperCase();

  if (!currentCardNum || !nextCardNum) {
    return res.status(400).json({ error: "current and new cardNum are required" });
  }

  try {
    const updated = await prisma.user.update({
      where: { cardNum: currentCardNum },
      data: { cardNum: nextCardNum }
    });
    return res.json(updated);
  } catch (error) {
    return res.status(400).json({ error: "Unable to update card", detail: error });
  }
});

router.delete("/cards/:cardNum", requireAdmin, async (req, res) => {
  const cardNum = (req.params.cardNum || "").toString().trim().toUpperCase();
  if (!cardNum) {
    return res.status(400).json({ error: "cardNum is required" });
  }
  try {
    await prisma.user.delete({ where: { cardNum } });
    return res.status(204).send();
  } catch (error) {
    return res.status(400).json({ error: "Unable to delete card", detail: error });
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

router.post("/door-state", requireAdmin, saveDoorState);
router.put("/door-state", requireAdmin, saveDoorState);

async function saveTempHumiRecord(req: Request, res: Response) {
  const temperature = Number(req.body.temperature ?? req.query.temperature);
  const humidity = Number(req.body.humidity ?? req.query.humidity);

  if (Number.isNaN(temperature) || Number.isNaN(humidity)) {
    return res.status(400).json({ error: "temperature and humidity are required" });
  }

  const totalCount = await prisma.tempHumi.count();
  let record;

  if (totalCount >= 25) {
    if (totalCount > 25) {
      const newestRows = await prisma.tempHumi.findMany({
        orderBy: [{ updatedTime: "desc" }, { id: "desc" }],
        take: 25,
        select: { id: true }
      });
      const newestIds = newestRows.map((row: { id: number }) => row.id);
      await prisma.tempHumi.deleteMany({
        where: { id: { notIn: newestIds } }
      });
    }

    const oldest = await prisma.tempHumi.findMany({
      orderBy: [{ updatedTime: "asc" }, { id: "asc" }],
      take: 1,
      select: { id: true }
    });

    record = await prisma.tempHumi.update({
      where: { id: oldest[0].id },
      data: { temperature, humidity, updatedTime: new Date() }
    });
  } else {
    record = await prisma.tempHumi.create({ data: { temperature, humidity } });
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
  const requestedLimit = Number(req.query.limit ?? 25);
  const limit = Number.isFinite(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 25) : 25;
  const data = await prisma.tempHumi.findMany({
    orderBy: { updatedTime: "desc" },
    take: limit
  });
  res.json(data.reverse());
});

export const apiRouter = router;
