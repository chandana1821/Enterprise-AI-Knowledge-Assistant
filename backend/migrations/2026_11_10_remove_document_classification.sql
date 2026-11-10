-- Remove obsolete document classification and clearance metadata.
-- This migration preserves documents, chunks, vectors, workspaces, and ACL grants.
BEGIN;

ALTER TABLE documents DROP COLUMN IF EXISTS classification;
ALTER TABLE document_chunks DROP COLUMN IF EXISTS classification;
ALTER TABLE users DROP COLUMN IF EXISTS clearance_level;
DROP TYPE IF EXISTS clearance;

COMMIT;
