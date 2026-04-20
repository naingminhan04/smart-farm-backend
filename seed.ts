import dotenv from "dotenv";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";

dotenv.config();

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });

const prisma = new PrismaClient({ adapter });

async function main() {
  // Seed DoorState - only one current state
  await prisma.doorState.upsert({
    where: { id: 1 },
    update: { state: "OFF" },
    create: { id: 1, state: "OFF" }
  });

  // Seed TempHumi - add 15 records with varying data
  const tempHumiData = [
    { temperature: 25.1, humidity: 60.0 },
    { temperature: 26.4, humidity: 65.2 },
    { temperature: 24.8, humidity: 58.7 },
    { temperature: 27.2, humidity: 62.1 },
    { temperature: 23.9, humidity: 55.8 },
    { temperature: 28.5, humidity: 68.3 },
    { temperature: 22.6, humidity: 52.4 },
    { temperature: 29.1, humidity: 70.9 },
    { temperature: 21.8, humidity: 49.6 },
    { temperature: 30.3, humidity: 73.5 },
    { temperature: 20.5, humidity: 46.2 },
    { temperature: 31.7, humidity: 76.8 },
    { temperature: 19.2, humidity: 42.9 },
    { temperature: 32.9, humidity: 79.4 },
    { temperature: 18.7, humidity: 40.1 }
  ];

  for (const data of tempHumiData) {
    await prisma.tempHumi.create({ data });
  }

  // Seed User - add some RFID cards
  const userData = [
    { cardNum: "A1B2C3D4" },
    { cardNum: "E5F6G7H8" },
    { cardNum: "I9J0K1L2" },
    { cardNum: "M3N4O5P6" },
    { cardNum: "Q7R8S9T0" }
  ];

  for (const data of userData) {
    await prisma.user.create({ data });
  }

  console.log("Seeding completed!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });