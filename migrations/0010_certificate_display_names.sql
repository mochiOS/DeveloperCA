ALTER TABLE certificates
ADD COLUMN display_name TEXT NOT NULL DEFAULT '' CHECK(length(display_name) <= 80);
