-- +goose Up
-- M5 security (SPEC §13): Kyverno install state per cluster, and indexes for
-- per-cluster replacement of image usage and the scanner queue.

CREATE TABLE kyverno_status (
  cluster_id   uuid PRIMARY KEY REFERENCES clusters(id) ON DELETE CASCADE,
  installed    boolean NOT NULL DEFAULT false,
  policy_count int NOT NULL DEFAULT 0,
  fail_count   int NOT NULL DEFAULT 0,
  reported_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX image_usage_cluster ON image_usage (cluster_id);
CREATE INDEX images_pending ON images (last_scanned_at NULLS FIRST, created_at) WHERE scan_status = 'pending';

-- +goose Down
DROP INDEX images_pending;
DROP INDEX image_usage_cluster;
DROP TABLE kyverno_status;
