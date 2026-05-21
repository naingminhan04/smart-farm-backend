import dotenv from "dotenv";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";

dotenv.config();

const connectionString =
  process.env.SUPABASE_DATABASE_URL?.trim() ||
  process.env.SUPABASE_DIRECT_URL?.trim() ||
  process.env.DATABASE_URL?.trim();

if (!connectionString) {
  throw new Error("Database connection string is missing. Set SUPABASE_DATABASE_URL or DATABASE_URL.");
}

const adapter = new PrismaPg({ connectionString });

export const prisma = new PrismaClient({ adapter });
