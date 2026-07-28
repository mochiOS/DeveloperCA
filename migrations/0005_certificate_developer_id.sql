ALTER TABLE developers ADD COLUMN certificate_developer_id TEXT NOT NULL DEFAULT '';

UPDATE developers
SET certificate_developer_id = 'org.mochios.developer.' || replace(lower(id), '-', '');

CREATE UNIQUE INDEX idx_developers_certificate_developer_id
ON developers(certificate_developer_id);
