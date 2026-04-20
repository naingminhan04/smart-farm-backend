# Smart Farm Backend

## Overview
Node.js TypeScript Express API for a smart farm project. It exposes routes under `/api` for status, configuration, RFID card numbers, door state, and temperature/humidity records.

## Project Structure
- `src/index.ts` starts the Express server.
- `src/routes.ts` defines API endpoints.
- `src/prisma.ts` initializes Prisma with PostgreSQL.
- `prisma/schema.prisma` defines `DoorState`, `TempHumi`, and `User` models.
- `prisma/migrations/` contains the initial PostgreSQL migration.

## Replit Setup
- Uses `SUPABASE_DATABASE_URL` when configured, otherwise falls back to the built-in PostgreSQL `DATABASE_URL`.
- Development workflow runs `HOST=127.0.0.1 PORT=3000 npm run dev`.
- Deployment is configured to build TypeScript and run the compiled server on port 5000.