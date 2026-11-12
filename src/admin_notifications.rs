use crate::store::number;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct Pending {
    id: String,
    payload_json: String,
    attempts: i64,
}

pub async fn enqueue(env: &Env, id: &str, mut payload: serde_json::Value) -> Result<()> {
    payload["event_id"] = id.into();
    env.d1("DB")?
        .prepare("INSERT OR IGNORE INTO admin_notification_outbox (id, payload_json, next_attempt_at) VALUES (?1, ?2, ?3)")
        .bind(&[id.into(), serde_json::to_string(&payload)?.into(), number(crate::now())])?
        .run().await?;
    Ok(())
}

// A response acknowledges delivery only after Discord succeeds (or the event is disabled).
// Pending rows survive request cancellation and are retried by the existing scheduled handler.
pub async fn drain(env: &Env) -> Result<()> {
    let db = env.d1("DB")?;
    let pending = db.prepare("SELECT id, payload_json, attempts FROM admin_notification_outbox WHERE next_attempt_at <= ?1 ORDER BY next_attempt_at, id LIMIT 10")
        .bind(&[number(crate::now())])?.all().await?.results::<Pending>()?;
    if pending.is_empty() {
        return Ok(());
    }
    let token = env
        .secret_store("ADMIN_NOTIFICATION_SERVICE_TOKEN")?
        .get()
        .await?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::RustError("admin notification token is unavailable".into()))?;
    let service = env.service("ADMIN_DASHBOARD")?;
    for row in pending {
        // Conditional claim prevents simultaneous fetch and cron invocations sending a row twice.
        let claimed = db.prepare("UPDATE admin_notification_outbox SET attempts = attempts + 1, next_attempt_at = ?1 WHERE id = ?2 AND attempts = ?3 AND next_attempt_at <= ?4")
            .bind(&[number(crate::now() + 60), row.id.as_str().into(), number(row.attempts), number(crate::now())])?
            .run().await?;
        if claimed.meta()?.and_then(|meta| meta.changes).unwrap_or(0) != 1 {
            continue;
        }
        let headers = Headers::new();
        headers.set("Content-Type", "application/json")?;
        headers.set("X-Admin-Notification-Token", &token)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(row.payload_json.into()));
        let request = Request::new_with_init(
            "https://admin.internal/api/internal/admin-notifications",
            &init,
        )?;
        match service.fetch_request(request).await {
            Ok(response) if response.status_code() == 200 => {
                db.prepare("DELETE FROM admin_notification_outbox WHERE id = ?1 AND attempts = ?2")
                    .bind(&[row.id.as_str().into(), number(row.attempts + 1)])?
                    .run()
                    .await?;
            }
            result => {
                let status = result
                    .as_ref()
                    .map(|response| response.status_code())
                    .unwrap_or(0);
                console_error!(
                    "admin notification pending id={} http_status={}",
                    row.id,
                    status
                );
                let delay = 60 * (1_i64 << row.attempts.min(4));
                db.prepare("UPDATE admin_notification_outbox SET next_attempt_at = ?1 WHERE id = ?2 AND attempts = ?3")
                    .bind(&[number(crate::now() + delay.min(900)), row.id.as_str().into(), number(row.attempts + 1)])?.run().await?;
            }
        }
    }
    Ok(())
}
