//! DEV ONLY (`--features dev-tools`, never built into the release image): `nzbd dev-totp`.
//!
//! Prints a currently acceptable TOTP code for the only user by decrypting the stored secret with
//! the configured (throwaway dev) key, so a demo needs no authenticator app. The production
//! Dockerfile builds without this feature; the command does not exist in that binary.

use std::time::Duration;

use nzb_store::prelude::*;
use nzb_web::totp;

use crate::config::{Config, load_key_file};

/// Prints a code whose step is newer than the last accepted one (replay protection), waiting up
/// to ~40 s for the next step when necessary.
pub fn run(cfg: &Config) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        let key = load_key_file(&cfg.security.totp_key_file).map_err(|e| e.to_string())?;
        let key = totp::TotpKey::from_slice(&key.0).ok_or("key must be 32 bytes")?;
        let db = crate::dbopen::open(cfg).await.map_err(|e| e.to_string())?;
        let user = db
            .get_only_user()
            .await
            .map_err(|e| e.to_string())?
            .ok_or("no user")?;
        let st = db
            .get_mfa_state(user.id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("no user")?;
        let blob = st
            .totp_secret_enc
            .ok_or("no TOTP secret yet: open the MFA enrollment page first")?;
        let secret = totp::open(&key, user.id, &blob).ok_or("cannot decrypt the TOTP secret")?;
        let last = st.totp_last_step.unwrap_or(-1);
        for _ in 0..40 {
            let now = crate::users::now_secs().div_euclid(30);
            // Highest step the server accepts (now + 1) that is newer than the last used one.
            for step in [now.saturating_add(1), now, now.saturating_sub(1)] {
                if step > last
                    && let Some(code) = totp::code_at(&secret, step)
                {
                    println!("{code}");
                    db.close().await;
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Err("no unused code available".to_owned())
    })
}
