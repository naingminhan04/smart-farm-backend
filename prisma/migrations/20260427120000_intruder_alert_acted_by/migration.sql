-- AlterTable
ALTER TABLE "IntruderAlert" ADD COLUMN "acknowledged_by_id" INTEGER;
ALTER TABLE "IntruderAlert" ADD COLUMN "emergency_dialed_by_id" INTEGER;

-- CreateIndex
CREATE INDEX "IntruderAlert_acknowledged_by_id_idx" ON "IntruderAlert"("acknowledged_by_id");
CREATE INDEX "IntruderAlert_emergency_dialed_by_id_idx" ON "IntruderAlert"("emergency_dialed_by_id");

-- AddForeignKey
ALTER TABLE "IntruderAlert" ADD CONSTRAINT "IntruderAlert_acknowledged_by_id_fkey" FOREIGN KEY ("acknowledged_by_id") REFERENCES "Admin"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "IntruderAlert" ADD CONSTRAINT "IntruderAlert_emergency_dialed_by_id_fkey" FOREIGN KEY ("emergency_dialed_by_id") REFERENCES "Admin"("id") ON DELETE SET NULL ON UPDATE CASCADE;
