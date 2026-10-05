// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Out-of-band storage change detection.
//!
//! NORA's own write paths (publish, proxy-cache, UI uploads) invalidate the
//! in-memory index and regenerate deb/rpm metadata themselves. This module
//! covers the *other* writer: a `.deb`/`.rpm`/raw file copied straight into
//! the data directory (Explorer, SCP, an external sync script) while the
//! server is running.
//!
//! Design:
//! - Polling fingerprint instead of inotify/ReadDirectoryChangesW: one
//!   portable scan that works on every platform (including the Windows
//!   filesystems this project targets) and every local storage layout, with
//!   no extra native dependencies.
//! - Only *user input* files are fingerprinted (`*.deb`, `*.rpm` and every
//!   raw key), never server-generated metadata (`Packages`, `Release`,
//!   `repodata/`, `.nora-meta/` sidecars), so a reindex can never retrigger
//!   itself.
//! - Changes are debounced (re-scanned after [`WatchConfig::settle_secs`]) so
//!   a half-written file does not get parsed mid-copy.
//! - deb/rpm repos with a diff are reconciled through the exact same
//!   `reindex_repo` core the `/deb/{repo}/-/reindex` / `/rpm/{repo}/-/reindex`
//!   handlers use, under the same per-repo publish lock.
//! - Every handled change invalidates all registry indexes and pushes a
//!   real-time refresh event to the web UI (EventSource/SSE), so the open
//!   dashboard and repository lists update without a reload.

use crate::config::WatchConfig;
use crate::registry::deb;
use crate::registry::rpm;
use crate::registry_type::RegistryType;
use crate::repo_index::RepoIndex;
use crate::signing::RepoSigner;
use crate::storage::Storage;
use crate::ui::UiEventBus;
use crate::PublishLocks;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Fingerprint of one watched artifact: storage key → (size, mtime-seconds).
/// Both fields change whenever a file is written, renamed or replaced, and
/// mtime granularity (1s on most filesystems) is enough for a registry watch.
type Fingerprint = BTreeMap<String, (u64, u64)>;

/// Storage prefixes whose contents are treated as *user input* (out-of-band
/// drops). Everything else (docker/npm/... proxy caches, generated metadata)
/// is written by NORA itself and must never trigger a reindex loop. See
/// [`is_watched_artifact`].
fn prefix_registry(prefix: &str) -> Option<RegistryType> {
    match prefix {
        "deb/" => Some(RegistryType::Deb),
        "rpm/" => Some(RegistryType::Rpm),
        "raw/" => Some(RegistryType::Raw),
        _ => None,
    }
}

/// Whether `key` is a user-input artifact the watcher should fingerprint.
///
/// Server-generated files are deliberately excluded:
/// - deb: `Packages`, `Packages.gz`, `Release`, `Release.gpg`, `InRelease`,
///   `dists/...`, `.nora-meta/...` — none end in `.deb`.
/// - rpm: `repodata/...` — excluded by the segment check; `.nora-meta/...`
///   sidecars do not end in `.rpm`.
/// - raw: every file under `raw/` is user data.
fn is_watched_artifact(key: &str) -> bool {
    if let Some(rest) = key.strip_prefix("deb/") {
        rest.to_ascii_lowercase().ends_with(".deb")
    } else if let Some(rest) = key.strip_prefix("rpm/") {
        rest.to_ascii_lowercase().ends_with(".rpm") && !rest.split('/').any(|s| s == "repodata")
    } else {
        key.starts_with("raw/")
    }
}

/// One full scan of the watched prefixes. `None` on a listing error — the
/// caller keeps the previous baseline so a transient storage failure cannot
/// masquerade as "nothing changed".
async fn snapshot(
    storage: &Storage,
    enabled_registries: &HashSet<RegistryType>,
) -> Option<Fingerprint> {
    let mut fp = Fingerprint::new();
    let keys = match storage.list_with_meta("").await {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "storage watch: list failed, keeping previous baseline");
            return None;
        }
    };
    for (key, meta) in keys {
        if is_watched_artifact(&key) {
            if let Some(prefix) = key.split('/').next().map(|p| format!("{p}/")) {
                if let Some(rt) = prefix_registry(&prefix) {
                    if enabled_registries.contains(&rt) {
                        fp.insert(key, (meta.size, meta.modified));
                    }
                }
            }
        }
    }
    Some(fp)
}

/// Repositories (second key segment) touched by a diff, per registry prefix.
/// `BTreeMap<RegistryType, BTreeSet<String>>` keeps ordering deterministic.
fn changed_repos(
    prev: &Fingerprint,
    now: &Fingerprint,
) -> HashMap<RegistryType, BTreeSet<String>> {
    let mut out: HashMap<RegistryType, BTreeSet<String>> = HashMap::new();
    for key in prev.keys().chain(now.keys()) {
        let Some((prefix, rest)) = key.split_once('/') else {
            continue;
        };
        let Some(rt) = prefix_registry(&format!("{prefix}/")) else {
            continue;
        };
        // prev[key] != now[key] — the file was added, removed or modified.
        if prev.get(key) != now.get(key) {
            if let Some(repo) = rest.split('/').next() {
                out.entry(rt).or_default().insert(repo.to_string());
            }
        }
    }
    out
}

/// Repositories that hold at least one artifact in the current fingerprint.
fn repos_with_artifacts(fp: &Fingerprint) -> HashMap<RegistryType, BTreeSet<String>> {
    let mut out: HashMap<RegistryType, BTreeSet<String>> = HashMap::new();
    for key in fp.keys() {
        let Some((prefix, rest)) = key.split_once('/') else {
            continue;
        };
        let Some(rt) = prefix_registry(&format!("{prefix}/")) else {
            continue;
        };
        if let Some(repo) = rest.split('/').next() {
            out.entry(rt).or_default().insert(repo.to_string());
        }
    }
    out
}

/// Run the out-of-band storage watcher until `cancel` fires.
///
/// First scan: adopts repos that look like a fresh out-of-band drop (they
/// hold packages but have no server-generated index yet), then records the
/// baseline. Every later scan diffs against the baseline; a real change is
/// debounced, reconciled (deb/rpm reindex under the repo publish lock),
/// index-invalidated and broadcast to the UI.
#[allow(clippy::too_many_arguments)]
pub async fn run_storage_watch(
    storage: Storage,
    repo_index: Arc<RepoIndex>,
    signer: Option<Arc<RepoSigner>>,
    enabled_registries: Arc<HashSet<RegistryType>>,
    publish_locks: PublishLocks,
    ui_events: Arc<UiEventBus>,
    cfg: WatchConfig,
    rpm_changelog_limit: usize,
    cancel: CancellationToken,
) {
    let mut baseline: Option<Fingerprint> = None;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(cfg.interval_secs.max(1)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    info!(
        interval_secs = cfg.interval_secs,
        settle_secs = cfg.settle_secs,
        "Out-of-band storage watcher started (deb/rpm/raw)"
    );

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Out-of-band storage watcher stopped");
                return;
            }
            _ = interval.tick() => {}
        }

        let Some(snap) = snapshot(&storage, &enabled_registries).await else {
            continue;
        };

        match &baseline {
            None => {
                // First scan. A repo holding packages but no generated index
                // was almost certainly created by dropping files while NORA
                // was stopped — adopt it now so `Packages`/`repodata` exist
                // before the first client asks. Existing repos are left alone
                // (their next out-of-band change reindexes them).
                for (rt, repos) in repos_with_artifacts(&snap) {
                    for repo in repos {
                        let index_exists = match rt {
                            RegistryType::Deb => {
                                storage.stat(&format!("deb/{repo}/Packages")).await.is_some()
                            }
                            RegistryType::Rpm => storage
                                .stat(&format!("rpm/{repo}/repodata/repomd.xml"))
                                .await
                                .is_some(),
                            _ => true, // raw has no generated index
                        };
                        if !index_exists {
                            // Adoption failures (e.g. an invalid package) are
                            // logged inside `reconcile_repo`; the first-scan
                            // baseline is still recorded so only real changes
                            // trigger later reindexes.
                            let _ = reconcile_repo(
                                rt,
                                &repo,
                                &storage,
                                signer.as_deref(),
                                &publish_locks,
                                rpm_changelog_limit,
                            )
                            .await;
                        }
                    }
                }
                if !snap.is_empty() {
                    info!(files = snap.len(), "storage watch: baseline established");
                }
                baseline = Some(snap);
            }
            Some(prev) => {
                if snap == *prev {
                    continue;
                }
                // Debounce: re-scan after the settle window. If the tree is
                // still changing, keep the old baseline and re-evaluate next
                // tick instead of parsing a half-written package.
                tokio::time::sleep(std::time::Duration::from_secs(cfg.settle_secs)).await;
                let Some(snap2) = snapshot(&storage, &enabled_registries).await else {
                    continue;
                };
                if snap2 != snap {
                    warn!("storage watch: tree still changing, deferring reindex");
                    continue;
                }

                let changed = changed_repos(prev, &snap2);
                if changed.is_empty() {
                    baseline = Some(snap2);
                    continue;
                }
                let mut transient_error = false;
                for (rt, repos) in &changed {
                    match rt {
                        RegistryType::Raw => {
                            info!(repos = repos.len(), "raw storage changed out-of-band");
                        }
                        RegistryType::Deb | RegistryType::Rpm => {
                            for repo in repos {
                                if reconcile_repo(
                                    *rt,
                                    repo,
                                    &storage,
                                    signer.as_deref(),
                                    &publish_locks,
                                    rpm_changelog_limit,
                                )
                                .await
                                .is_err()
                                {
                                    transient_error = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }

                // Mark only the affected registry indexes dirty so the next
                // UI read rebuilds just those (an out-of-band deb drop must
                // never force a full rescan of the docker/npm/... proxy caches
                // — rebuilding all nine registries on the request path is what
                // made pages stall after a change). Then push a real-time
                // refresh event to open pages.
                for rt in changed.keys() {
                    let name = rt.as_str();
                    repo_index.invalidate(name);
                    info!(registry = name, "registry index invalidated after out-of-band change");
                }
                let generation = ui_events.notify_changed();
                info!(
                    generation,
                    deb_repos = changed.get(&RegistryType::Deb).map_or(0, |s| s.len()),
                    rpm_repos = changed.get(&RegistryType::Rpm).map_or(0, |s| s.len()),
                    raw = changed.contains_key(&RegistryType::Raw),
                    "out-of-band change handled, index invalidated, UI notified"
                );

                // Keep the previous baseline on a transient storage failure so
                // the next tick retries the failed repo; acked changes (or a
                // permanently invalid package) move the baseline forward.
                if !transient_error {
                    baseline = Some(snap2);
                }
            }
        }
    }
}

/// Reconcile one deb/rpm repository (adopt new packages, drop orphan
/// sidecars, regenerate `Packages`/`repodata`) under the per-repo publish
/// lock. Returns `Ok(())` when the repo was reconciled (or vanished), `Err`
/// on a storage failure that should be retried.
async fn reconcile_repo(
    rt: RegistryType,
    repo: &str,
    storage: &Storage,
    signer: Option<&RepoSigner>,
    publish_locks: &PublishLocks,
    rpm_changelog_limit: usize,
) -> Result<(), ()> {
    let lock_key = match rt {
        RegistryType::Deb => deb::release_key(repo),
        RegistryType::Rpm => rpm::repomd_key(repo),
        _ => return Ok(()),
    };
    let lock = crate::acquire_publish_lock(publish_locks, &lock_key);
    let _guard = lock.lock().await;

    match rt {
        RegistryType::Deb => match deb::reindex_repo(storage, signer, repo).await {
            Ok(s) => {
                info!(
                    repo = %repo,
                    packages = s.packages,
                    sidecars_created = s.sidecars_created,
                    orphans_removed = s.orphans_removed,
                    "deb reindexed after out-of-band change"
                );
                Ok(())
            }
            Err(deb::ReindexError::NotFound) => {
                info!(repo = %repo, "deb repo vanished, skipping");
                Ok(())
            }
            Err(deb::ReindexError::InvalidPackage(msg)) => {
                warn!(repo = %repo, error = %msg, "deb reindex skipped: invalid package");
                Ok(())
            }
            Err(deb::ReindexError::Storage(msg)) => {
                error!(repo = %repo, error = %msg, "deb reindex failed; will retry");
                Err(())
            }
        },
        RegistryType::Rpm => {
            match rpm::reindex_repo(storage, signer, repo, rpm_changelog_limit).await {
                Ok(s) => {
                    info!(
                        repo = %repo,
                        packages = s.packages,
                        sidecars_created = s.sidecars_created,
                        orphans_removed = s.orphans_removed,
                        "rpm reindexed after out-of-band change"
                    );
                    Ok(())
                }
                Err(rpm::ReindexError::NotFound) => {
                    info!(repo = %repo, "rpm repo vanished, skipping");
                    Ok(())
                }
                Err(rpm::ReindexError::InvalidPackage(msg)) => {
                    warn!(repo = %repo, error = %msg, "rpm reindex skipped: invalid package");
                    Ok(())
                }
                Err(rpm::ReindexError::Storage(msg)) => {
                    error!(repo = %repo, error = %msg, "rpm reindex failed; will retry");
                    Err(())
                }
            }
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fp(entries: &[(&str, u64, u64)]) -> Fingerprint {
        entries
            .iter()
            .map(|(k, size, mtime)| ((*k).to_string(), (*size, *mtime)))
            .collect()
    }

    #[test]
    fn artifact_filter_excludes_generated_files() {
        assert!(is_watched_artifact("deb/myrepo/pool/main/a/foo.deb"));
        assert!(is_watched_artifact("deb/myrepo/foo_1.0_all.deb"));
        assert!(!is_watched_artifact("deb/myrepo/Packages"));
        assert!(!is_watched_artifact("deb/myrepo/Packages.gz"));
        assert!(!is_watched_artifact("deb/myrepo/Release"));
        assert!(!is_watched_artifact("deb/myrepo/.nora-meta/foo.json"));
        assert!(!is_watched_artifact("deb/myrepo/dists/bookworm/main/binary-amd64/Packages"));
        assert!(is_watched_artifact("rpm/myrepo/foo-1.0-1.x86_64.rpm"));
        assert!(!is_watched_artifact("rpm/myrepo/repodata/repomd.xml"));
        assert!(!is_watched_artifact("rpm/myrepo/.nora-meta/foo.json"));
        assert!(is_watched_artifact("raw/notes.txt"));
        assert!(is_watched_artifact("raw/sub/dir/data.bin"));
        assert!(!is_watched_artifact("npm/lodash/tarballs/lodash.tgz"));
        assert!(!is_watched_artifact(".nora-pins.ndjson"));
    }

    /// Apply the same artifact filter `snapshot` uses, so fingerprints only
    /// ever contain user-input files (never server-generated metadata).
    fn artifact_only(fp: &Fingerprint) -> Fingerprint {
        fp.iter()
            .filter(|(k, _)| is_watched_artifact(k))
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    #[test]
    fn changed_repos_tracks_add_remove_modify() {
        // deb/a: same size+mtime → unchanged; deb/c added; rpm/b modified;
        // raw/f untouched.
        let prev = fp(&[("deb/a/one.deb", 10, 1), ("rpm/b/two.rpm", 20, 2), ("raw/f", 30, 3)]);
        let now = fp(&[
            ("deb/a/one.deb", 10, 1),
            ("deb/c/three.deb", 40, 4),
            ("rpm/b/two.rpm", 21, 2),
            ("raw/f", 30, 3),
        ]);
        let changed = changed_repos(&prev, &now);
        assert!(changed.contains_key(&RegistryType::Deb));
        assert_eq!(
            changed.get(&RegistryType::Deb).unwrap(),
            &BTreeSet::from(["c".to_string()])
        );
        assert_eq!(
            changed.get(&RegistryType::Rpm).unwrap(),
            &BTreeSet::from(["b".to_string()])
        );
        assert!(!changed.contains_key(&RegistryType::Raw)); // raw/f unchanged

        // A modified package is also a change.
        let prev2 = fp(&[("deb/a/one.deb", 10, 1)]);
        let now2 = fp(&[("deb/a/one.deb", 11, 1)]);
        assert_eq!(
            changed_repos(&prev2, &now2).get(&RegistryType::Deb).unwrap(),
            &BTreeSet::from(["a".to_string()])
        );
    }

    #[test]
    fn changed_repos_ignores_server_generated_writes() {
        // Reindex writes Packages/Release/repodata — after the artifact filter
        // (which `snapshot` applies), those keys never enter the fingerprint,
        // so the post-reindex fingerprint equals the pre-reindex one and a
        // reindex can never retrigger itself.
        let prev = fp(&[("deb/a/one.deb", 10, 1)]);
        let now = fp(&[
            ("deb/a/one.deb", 10, 1),
            ("deb/a/Packages", 5, 9),
            ("deb/a/Release", 5, 9),
            ("deb/a/.nora-meta/one.deb.json", 5, 9),
            ("deb/a/repodata/repomd.xml", 5, 9),
        ]);
        assert_eq!(artifact_only(&prev), artifact_only(&now));
        assert!(changed_repos(&artifact_only(&prev), &artifact_only(&now)).is_empty());
    }
}
