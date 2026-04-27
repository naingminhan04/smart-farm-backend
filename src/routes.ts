import { Request, Response, Router } from "express";
import { prisma } from "./prisma.js";
import { adminRouter, requireAdmin } from "./adminAuth.js";
import { oauthRouter } from "./oauth.js";

const router = Router();
const intruderHistoryLimit = 20;

router.use("/admin", adminRouter);
router.use("/auth", oauthRouter);

router.get("/status", async (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
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

async function pruneIntruderAlertHistory() {
  const newestRows = await prisma.intruderAlert.findMany({
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: intruderHistoryLimit,
    select: { id: true }
  });

  if (newestRows.length < intruderHistoryLimit) return;

  await prisma.intruderAlert.deleteMany({
    where: {
      id: {
        notIn: newestRows.map((row: { id: number }) => row.id)
      }
    }
  });
}

type AdminBrief = { id: number; username: string } | null;

function toIntruderAlertPayload(alert: {
  id: number;
  source: string;
  message: string;
  detectedAt: Date;
  clearedAt: Date | null;
  acknowledgedAt: Date | null;
  acknowledgedById: number | null;
  emergencyDialedAt: Date | null;
  emergencyDialedById: number | null;
  createdAt: Date;
  updatedAt: Date;
  acknowledgedBy?: AdminBrief;
  emergencyDialedBy?: AdminBrief;
}) {
  const { acknowledgedBy = null, emergencyDialedBy = null, ...rest } = alert;
  return {
    ...rest,
    acknowledgedBy,
    acknowledgedByUsername: acknowledgedBy?.username ?? null,
    emergencyDialedBy,
    emergencyDialedByUsername: emergencyDialedBy?.username ?? null,
    requiresAction: !alert.acknowledgedAt && !alert.emergencyDialedAt
  };
}

const intruderAlertInclude = {
  acknowledgedBy: { select: { id: true, username: true } },
  emergencyDialedBy: { select: { id: true, username: true } }
} as const;

async function getPendingIntruderAlert() {
  return prisma.intruderAlert.findFirst({
    where: {
      acknowledgedAt: null,
      emergencyDialedAt: null
    },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    include: intruderAlertInclude
  });
}

router.get("/intruder-alerts", requireAdmin, async (_req, res) => {
  const [activeAlert, history] = await Promise.all([
    getPendingIntruderAlert(),
    prisma.intruderAlert.findMany({
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: intruderHistoryLimit,
      include: intruderAlertInclude
    })
  ]);

  res.json({
    activeAlert: activeAlert ? toIntruderAlertPayload(activeAlert) : null,
    history: history.map(toIntruderAlertPayload)
  });
});

router.post("/intruder-alerts/report", async (req, res) => {
  const detected = req.body.detected ?? req.query.detected;
  const source = (req.body.source ?? req.query.source ?? "laser-fence").toString().trim() || "laser-fence";
  const message =
    (req.body.message ?? req.query.message ?? "Intruder detected by laser fence.").toString().trim() ||
    "Intruder detected by laser fence.";

  const isDetected =
    detected === true ||
    detected === "true" ||
    detected === 1 ||
    detected === "1" ||
    detected === "HIGH" ||
    detected === "high";

  const isCleared =
    detected === false ||
    detected === "false" ||
    detected === 0 ||
    detected === "0" ||
    detected === "LOW" ||
    detected === "low";

  if (!isDetected && !isCleared) {
    return res.status(400).json({ error: "detected must be true/false" });
  }

  const pendingAlert = await getPendingIntruderAlert();

  if (isDetected) {
    if (pendingAlert) {
      const updated = await prisma.intruderAlert.update({
        where: { id: pendingAlert.id },
        data: {
          source,
          message,
          detectedAt: new Date(),
          clearedAt: null
        },
        include: intruderAlertInclude
      });
      return res.json({ alert: toIntruderAlertPayload(updated), created: false });
    }

    const created = await prisma.intruderAlert.create({
      data: {
        source,
        message
      },
      include: intruderAlertInclude
    });
    await pruneIntruderAlertHistory();
    return res.status(201).json({ alert: toIntruderAlertPayload(created), created: true });
  }

  if (!pendingAlert) {
    return res.json({ alert: null, created: false });
  }

  const cleared = await prisma.intruderAlert.update({
    where: { id: pendingAlert.id },
    data: {
      clearedAt: pendingAlert.clearedAt ?? new Date()
    },
    include: intruderAlertInclude
  });
  return res.json({ alert: toIntruderAlertPayload(cleared), created: false });
});

router.post("/intruder-alerts/:id/acknowledge", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) {
    return res.status(400).json({ error: "Invalid alert id" });
  }

  const adminId = Number(res.locals.adminId);

  try {
    const alert = await prisma.intruderAlert.update({
      where: { id },
      data: {
        acknowledgedAt: new Date(),
        acknowledgedById: Number.isFinite(adminId) ? adminId : null
      },
      include: intruderAlertInclude
    });
    return res.json(toIntruderAlertPayload(alert));
  } catch (error) {
    return res.status(404).json({ error: "Intruder alert not found", detail: error });
  }
});

router.post("/intruder-alerts/:id/emergency", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) {
    return res.status(400).json({ error: "Invalid alert id" });
  }

  const adminId = Number(res.locals.adminId);

  try {
    const alert = await prisma.intruderAlert.update({
      where: { id },
      data: {
        emergencyDialedAt: new Date(),
        emergencyDialedById: Number.isFinite(adminId) ? adminId : null
      },
      include: intruderAlertInclude
    });
    return res.json(toIntruderAlertPayload(alert));
  } catch (error) {
    return res.status(404).json({ error: "Intruder alert not found", detail: error });
  }
});

export const apiRouter = router;
