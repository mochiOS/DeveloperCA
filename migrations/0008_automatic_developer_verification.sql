UPDATE developers
SET verification_status = 'verified',
    updated_at = unixepoch()
WHERE status = 'active'
  AND verification_status = 'pending';
