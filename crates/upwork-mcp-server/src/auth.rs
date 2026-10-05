//! Proactive OAuth Token Vault with Atomic File Locking and Single-Flight Refresh.
//!
//! Provides:
//! - Secure on-disk token caching protected by POSIX advisory file locking (`libc::flock`).
//! - Proactive token refresh when Time-To-Live (TTL) drops below 300 seconds.
//! - Single-flight deduplication ensuring concurrent requests never duplicate OAuth refresh calls.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

/// Errors arising during token storage, validation, or refresh operations.
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("I/O error during token vault operation: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("OAuth token refresh failed: {0}")]
    Refresh(String),

    #[error("Token invalid or expired: {0}")]
    InvalidToken(String),
}

/// Upwork OAuth 2.0 Token record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at_epoch_secs: u64,
}

/// Trait defining the asynchronous OAuth token refresh contract.
pub trait TokenRefresher: Send + Sync {
    fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> impl std::future::Future<Output = Result<OAuthToken, String>> + Send;
}

/// Default placeholder refresher when no network refresher is configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultTokenRefresher;

impl TokenRefresher for DefaultTokenRefresher {
    async fn refresh_token(&self, _refresh_token: &str) -> Result<OAuthToken, String> {
        Err("No default refresher configured".into())
    }
}

/// Token Vault managing on-disk storage, concurrency deduplication, and proactive refresh.
pub struct TokenVault<R: TokenRefresher = DefaultTokenRefresher> {
    file_path: PathBuf,
    refresher: Arc<R>,
    refresh_mutex: Mutex<()>,
}

impl<R: TokenRefresher> TokenVault<R> {
    /// Constructs a new `TokenVault` targeting the specified file path.
    pub fn new(file_path: PathBuf, refresher: Arc<R>) -> Self {
        Self {
            file_path,
            refresher,
            refresh_mutex: Mutex::new(()),
        }
    }

    /// Atomically writes an `OAuthToken` to disk using POSIX `flock(LOCK_EX)`.
    pub fn save_to_disk(path: &Path, token: &OAuthToken) -> Result<(), AuthError> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        let fd = file.as_raw_fd();
        let lock_res = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if lock_res != 0 {
            return Err(AuthError::Io(std::io::Error::last_os_error()));
        }

        let serialized = serde_json::to_vec_pretty(token)?;
        let mut writer = file;
        let write_res = writer
            .write_all(&serialized)
            .and_then(|_| writer.sync_all());

        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }

        write_res.map_err(AuthError::Io)
    }

    /// Atomically reads an `OAuthToken` from disk using POSIX `flock(LOCK_SH)`.
    pub fn load_from_disk(path: &Path) -> Result<OAuthToken, AuthError> {
        let mut file = OpenOptions::new().read(true).open(path)?;

        let fd = file.as_raw_fd();
        let lock_res = unsafe { libc::flock(fd, libc::LOCK_SH) };
        if lock_res != 0 {
            return Err(AuthError::Io(std::io::Error::last_os_error()));
        }

        let mut contents = String::new();
        let read_res = file.read_to_string(&mut contents);

        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }

        read_res?;
        let token: OAuthToken = serde_json::from_str(&contents)?;
        Ok(token)
    }

    /// Retrieves a valid access token.
    ///
    /// If the token has less than 300 seconds TTL remaining, proactive refresh is triggered.
    /// Concurrent callers are serialized via a single-flight mutex to avoid duplicate refresh calls.
    pub async fn get_access_token(&self) -> Result<String, AuthError> {
        let now_secs = chrono::Utc::now().timestamp().max(0) as u64;

        // 1. Check current token on disk
        if let Ok(current) = Self::load_from_disk(&self.file_path) {
            if current.expires_at_epoch_secs > now_secs.saturating_add(300) {
                return Ok(current.access_token);
            }
        }

        // 2. Token needs proactive refresh: acquire single-flight mutex
        let _guard = self.refresh_mutex.lock().await;

        // 3. Double-check token after acquiring lock in case another task refreshed it
        let current = Self::load_from_disk(&self.file_path)?;
        let refreshed_now_secs = chrono::Utc::now().timestamp().max(0) as u64;
        if current.expires_at_epoch_secs > refreshed_now_secs.saturating_add(300) {
            return Ok(current.access_token);
        }

        // 4. Execute single-flight refresh
        let refreshed = self
            .refresher
            .refresh_token(&current.refresh_token)
            .await
            .map_err(AuthError::Refresh)?;

        Self::save_to_disk(&self.file_path, &refreshed)?;
        Ok(refreshed.access_token)
    }
}
