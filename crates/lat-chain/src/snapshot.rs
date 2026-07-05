//! Ledger snapshot persistence (L8).
//!
//! The block log is the source of truth, but replaying it from genesis re-runs
//! every PoW check and zero-knowledge proof — startup cost grows with chain
//! length. A snapshot caches the full ledger at one block so boot becomes
//! `load snapshot + replay only the tail`.
//!
//! Trust model: a snapshot is a *cache*, never an authority. Before it is used,
//! the chain layer recomputes the decoded ledger's `state_root` and requires it
//! to equal the root committed in that block's PoW-bound header. A corrupt,
//! stale, or tampered snapshot therefore can't inject state — it is simply
//! ignored and the node falls back to full replay.
//!
//! File format: `MAGIC | height u64 | block_id [32] | blake3(body) [32] |
//! body_len u32 | body`, where `body` is [`Ledger::encode`]. The checksum
//! rejects torn files cheaply; the state-root check is what makes it sound.
//! Writes go to a temp file then rename, so a crash mid-write leaves the old
//! snapshot intact.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use lat_state::Ledger;

const MAGIC: &[u8; 8] = b"LATSNAP1";

/// A decoded snapshot: the ledger as it stood right after `block_id` (at
/// `height`) was applied.
pub struct Snapshot {
    pub height: u64,
    pub block_id: [u8; 32],
    pub ledger: Ledger,
}

/// The snapshot path for a block log at `log_path` (sibling `<log>.snap` file).
pub fn snapshot_path(log_path: &Path) -> PathBuf {
    let mut os = log_path.as_os_str().to_owned();
    os.push(".snap");
    PathBuf::from(os)
}

/// Atomically write a snapshot of `ledger` at (`height`, `block_id`) to `path`.
pub fn write(path: &Path, height: u64, block_id: &[u8; 32], ledger: &Ledger) -> io::Result<()> {
    let body = ledger.encode();
    let mut v = Vec::with_capacity(8 + 8 + 32 + 32 + 4 + body.len());
    v.extend_from_slice(MAGIC);
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(block_id);
    v.extend_from_slice(blake3::hash(&body).as_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&body);

    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);
    fs::write(&tmp, &v)?;
    fs::rename(&tmp, path)
}

/// Read and decode the snapshot at `path`. `None` on any problem — missing
/// file, bad magic, checksum mismatch, undecodable ledger — because every
/// failure has the same correct handling: fall back to full replay.
pub fn read(path: &Path) -> Option<Snapshot> {
    let b = fs::read(path).ok()?;
    if b.get(0..8)? != MAGIC {
        return None;
    }
    let height = u64::from_le_bytes(b.get(8..16)?.try_into().ok()?);
    let block_id: [u8; 32] = b.get(16..48)?.try_into().ok()?;
    let sum: [u8; 32] = b.get(48..80)?.try_into().ok()?;
    let len = u32::from_le_bytes(b.get(80..84)?.try_into().ok()?) as usize;
    let body = b.get(84..84usize.checked_add(len)?)?;
    if 84 + len != b.len() {
        return None;
    }
    if blake3::hash(body).as_bytes() != &sum {
        return None;
    }
    let ledger = Ledger::decode(body)?;
    Some(Snapshot { height, block_id, ledger })
}
