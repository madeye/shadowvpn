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

use crate::{helper, runner, AppState};

/// How often the watcher re-derives the run status.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// First retry delay after a failed reconnect attempt.
const BACKOFF_START: Duration = Duration::from_secs(2);

/// Retry delays double up to this cap, then stay there.
const BACKOFF_CAP: Duration = Duration::from_secs(60);

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
