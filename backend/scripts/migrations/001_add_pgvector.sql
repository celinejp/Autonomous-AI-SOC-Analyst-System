-- Migration: Add pgvector extension and embedding columns
-- Run this migration to enable semantic search

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Add embedding column to incidents table (768 dimensions for nomic-embed-text)
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS embedding vector(768);

-- Add searchable text column for generating embeddings
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS search_text TEXT;

-- Create IVFFlat index for fast cosine similarity search
-- Note: Index requires at least 100 rows to be effective
CREATE INDEX IF NOT EXISTS incidents_embedding_idx 
ON incidents USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- Create index on search_text for filtering
CREATE INDEX IF NOT EXISTS incidents_search_text_idx ON incidents USING gin(to_tsvector('english', search_text));

-- Add embedding column to incident_reports for searching by report content
ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS embedding vector(768);

CREATE INDEX IF NOT EXISTS incident_reports_embedding_idx 
ON incident_reports USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

