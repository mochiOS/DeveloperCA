UPDATE certificate_requests
SET status = 'rejected',
    processed_at = unixepoch(),
    rejection_reason = 'Legacy pending request; resubmit for automatic issuance',
    updated_at = unixepoch()
WHERE status = 'pending';

DROP TABLE developer_package_scopes;
DROP TABLE developer_capability_grants;
DROP TABLE global_issuable_capabilities;
