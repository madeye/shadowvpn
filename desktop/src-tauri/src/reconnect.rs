//! Auto-reconnect watcher: brings the tunnel back when the client dies
//! without a user-initiated disconnect (a transient error the client treats
//! as fatal, a crash, an elevated kill from outside the app).
//!
//! Intent lives in `AppState.active_profile`: `connect` records the profile,
//! `disconnect` clears it. The watcher polls the disk-derived status and,
//! when the intent says "up" but the client is gone, re-runs the shared
//! connect path — but only while the elevated helper is still alive, so a
//! reconnect never pops a credential prompt at a random moment. Attempts
//! back off exponentially (2s → 60s) so a hard-down network isn't hammered.

use std::time::{Duration, Instant};

use tauri::Manager;

use crate::{helper, helper_ipc::Cmd, runner, settings, AppState};

/// How often the watcher re-derives the run status.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// First retry delay after a failed reconnect attempt.
const BACKOFF_START: Duration = Duration::from_secs(2);

/// Retry delays double up to this cap, then stay there.
const BACKOFF_CAP: Duration = Duration::from_secs(60);

/// Journal the client writes next to its own binary before touching the
/// resolver (`shadowvpn::policy::dnsconf::JOURNAL_FILE_NAME` — hard-coded
/// here because the desktop crate does not depend on the client crate; keep
/// the two in sync).
const JOURNAL_FILE_NAME: &str = "dns-restore.json";

/// Minimum spacing between `--restore-dns` attempts, so a restore that keeps
/// failing doesn't respawn the client binary every poll tick.
const DNS_RESTORE_RETRY: Duration = Duration::from_secs(60);

/// Spawn the watcher thread for the lifetime of the app.
pub fn spawn(app: tauri::AppHandle) {
    std::thread::Builder::new()
        .name("reconnect-watcher".to_string())
        .spawn(move || watch(app))
        .expect("failed to spawn reconnect watcher");
}

fn watch(app: tauri::AppHandle) {
    let mut backoff = BACKOFF_START;
    let mut next_attempt = Instant::now();
    let mut next_dns_restore = Instant::now();

    loop {
        std::thread::sleep(POLL_INTERVAL);

        let state = app.state::<AppState>();
        // Serialize with the user's connect/disconnect commands so the two
        // can never race (e.g. reconnecting a tunnel mid-disconnect).
        let Ok(_guard) = state.lock.lock() else {
            continue;
        };
        let Ok(mut active) = state.active_profile.lock() else {
            continue;
        };

        let status = runner::current_status(&app);
        match status.state.as_str() {
            "connected" => {
                // Adopt a run this GUI session didn't start (the app was
                // restarted while a tunnel ran) so it too gets watched.
                if active.is_none() {
                    *active = status.profile.clone();
                }
                backoff = BACKOFF_START;
                next_attempt = Instant::now();
            }
            "disconnected" => {
                // No client running: if a crashed run left a DNS restore
                // journal behind, heal the resolver now — promptless, through
                // the elevated helper. Done before (and independently of) any
                // reconnect, so DNS comes back even when the user isn't
                // reconnecting or every reconnect attempt fails.
                maybe_restore_dns(&app, &mut next_dns_restore);

                let Some(profile) = active.clone() else {
                    continue;
                };
                if Instant::now() < next_attempt {
                    continue;
                }
                // Reconnect only through a live helper (promptless). With the
                // helper gone, a reconnect would raise a credential dialog out
                // of nowhere — drop the intent and leave it to the user.
                if helper::ping(&app).is_none() {
                    eprintln!(
                        "[reconnect] client for profile '{profile}' is down and the \
                         elevated helper is gone; not reconnecting without a prompt"
                    );
                    *active = None;
                    continue;
                }
                match runner::do_connect(&app, &profile) {
                    Ok(_) => {
                        eprintln!("[reconnect] client for profile '{profile}' died; reconnected");
                        backoff = BACKOFF_START;
                        next_attempt = Instant::now();
                    }
                    Err(e) => {
                        eprintln!(
                            "[reconnect] reconnect of profile '{profile}' failed \
                             (next attempt in {}s): {e}",
                            backoff.as_secs()
                        );
                        next_attempt = Instant::now() + backoff;
                        backoff = (backoff * 2).min(BACKOFF_CAP);
                    }
                }
            }
            // "connecting": a run is already being brought up; leave it alone.
            _ => {}
        }
    }
}

/// If a run died without restoring the system resolver, its journal is still
/// sitting next to the client binary — ask the elevated helper to run
/// `shadowvpn-client --restore-dns` to heal DNS. No-ops (cheaply) when there
/// is no journal; attempts are spaced by [`DNS_RESTORE_RETRY`].
///
/// Only ever goes through a live helper: with the helper gone, restoring
/// would raise a credential prompt out of nowhere, and the next `apply` in
/// the client self-heals from the journal anyway.
fn maybe_restore_dns(app: &tauri::AppHandle, next_attempt: &mut Instant) {
    if Instant::now() < *next_attempt {
        return;
    }
    let Ok(settings_info) = settings::get_settings(app.clone()) else {
        return;
    };
    let Some(bin) = settings_info.resolved_client_bin else {
        return;
    };
    let journal_present = std::path::Path::new(&bin)
        .parent()
        .map(|dir| dir.join(JOURNAL_FILE_NAME).exists())
        .unwrap_or(false);
    if !journal_present {
        return;
    }
    // The helper refuses RestoreDns while it supervises a client; skip the
    // round-trip when a ping already says so (a client this GUI's status
    // derivation doesn't know about, e.g. mid-connect from another session).
    match helper::ping(app) {
        None => return,
        Some(resp) if resp.running == Some(true) => return,
        Some(_) => {}
    }

    *next_attempt = Instant::now() + DNS_RESTORE_RETRY;
    match helper::call(app, Cmd::RestoreDns) {
        Ok(r) if r.ok => {
            eprintln!("[reconnect] restored system DNS from the journal a crashed run left behind");
        }
        Ok(r) => {
            eprintln!(
                "[reconnect] DNS restore failed (retrying in {}s): {}",
                DNS_RESTORE_RETRY.as_secs(),
                r.error
                    .unwrap_or_else(|| "unknown helper error".to_string())
            );
        }
        Err(e) => {
            eprintln!(
                "[reconnect] DNS restore failed (retrying in {}s): {e}",
                DNS_RESTORE_RETRY.as_secs()
            );
        }
    }
}
