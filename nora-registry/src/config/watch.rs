// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Out-of-band storage watch configuration.
//!
//! NORA can watch the storage tree for files that arrive, change or disappear
//! *outside* the registry APIs (a `.deb` copied straight into the data
//! directory, an `.rpm` synced by an external script, a raw file dropped in
//! with Explorer/SCP). When such a change is detected it invalidates the
//! in-memory index, reconciles deb/rpm repositories (rebuilding `Packages` /
//! `repodata`) and pushes a real-time refresh event to the web UI.

use serde::{Deserialize, Serialize};
use std::env;

/// Storage-watch (out-of-band change detection) configuration.
///
/// # Environment Variables
/// - `NORA_WATCH_ENABLED` — enable/disable the background scan (default: true)
/// - `NORA_WATCH_INTERVAL` — seconds between scans (default: 5)
/// - `NORA_WATCH_SETTLE` — extra seconds to wait for a mid-copy tree to
///   stabilise before reindexing (default: 2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    /// Master switch for the out-of-band change detector. Only meaningful for
    /// the local storage backend (a filesystem watch makes no sense on S3/GCS,
    /// where a full LIST per tick would be expensive).
    #[serde(default = "default_watch_enabled")]
    pub enabled: bool,
    /// Seconds between storage scans.
    #[serde(default = "default_watch_interval")]
    pub interval_secs: u64,
    /// After a change is observed, wait this many extra seconds and re-scan:
    /// if the tree is still changing (a file is mid-copy) the reindex is
    /// postponed to the next tick instead of parsing a half-written package.
    #[serde(default = "default_watch_settle")]
    pub settle_secs: u64,
}

fn default_watch_enabled() -> bool {
    true
}

fn default_watch_interval() -> u64 {
    5
}

fn default_watch_settle() -> u64 {
    2
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 5,
            settle_secs: 2,
        }
    }
}

impl WatchConfig {
    /// Apply environment variable overrides for watch config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_WATCH_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_WATCH_INTERVAL") {
            super::parse_env_warn("NORA_WATCH_INTERVAL", &val, &mut self.interval_secs);
        }
        if let Ok(val) = env::var("NORA_WATCH_SETTLE") {
            super::parse_env_warn("NORA_WATCH_SETTLE", &val, &mut self.settle_secs);
        }
    }
}
