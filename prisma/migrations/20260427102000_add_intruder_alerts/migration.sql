-- CreateTable
CREATE TABLE "IntruderAlert" (
    "id" SERIAL NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'laser-fence',
    "message" TEXT NOT NULL DEFAULT 'Intruder detected by laser fence.',
    "detected_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "cleared_at" TIMESTAMP(3),
    "acknowledged_at" TIMESTAMP(3),
    "emergency_dialed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IntruderAlert_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "IntruderAlert_created_at_idx" ON "IntruderAlert"("created_at");

-- CreateIndex
CREATE INDEX "IntruderAlert_acknowledged_at_idx" ON "IntruderAlert"("acknowledged_at");

-- CreateIndex
CREATE INDEX "IntruderAlert_emergency_dialed_at_idx" ON "IntruderAlert"("emergency_dialed_at");
