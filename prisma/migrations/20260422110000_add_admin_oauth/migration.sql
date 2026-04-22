-- AlterTable
ALTER TABLE "Admin" ADD COLUMN "email" TEXT;
ALTER TABLE "Admin" ALTER COLUMN "password_hash" DROP NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "Admin_email_key" ON "Admin"("email");

-- CreateTable
CREATE TABLE "AdminIdentity" (
    "id" SERIAL NOT NULL,
    "admin_id" INTEGER NOT NULL,
    "provider" TEXT NOT NULL,
    "provider_subject" TEXT NOT NULL,
    "email" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AdminIdentity_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "AdminIdentity_provider_provider_subject_key" ON "AdminIdentity"("provider", "provider_subject");
CREATE INDEX "AdminIdentity_admin_id_idx" ON "AdminIdentity"("admin_id");

-- AddForeignKey
ALTER TABLE "AdminIdentity" ADD CONSTRAINT "AdminIdentity_admin_id_fkey" FOREIGN KEY ("admin_id") REFERENCES "Admin"("id") ON DELETE CASCADE ON UPDATE CASCADE;
