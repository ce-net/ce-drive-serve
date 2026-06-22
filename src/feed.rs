//! The per-drive change feed — a monotonic `seq` log of `(path, node_id, kind, etag)` deltas.
//!
//! This is the source of truth for sync ([`DriveOp::Poll`](crate::wire::DriveOp::Poll)): it is
//! gap-free, resumable, and carries paths + etags (never bytes), exactly Google Drive's
//! `changes.list` contract. The pubsub beacon ([`DriveOp::Watch`](crate::wire::DriveOp::Watch)) is
//! only a latency hint that wakes a client to call `Poll`; the cursor here is the truth.

use crate::wire::{Change, ChangeKind};

/// An append-only, monotonic change log for one drive. `seq` starts at 0 (nothing seen) and is the
/// `seq` of the last recorded change; a `Poll{cursor}` returns changes with `seq > cursor`.
#[derive(Debug, Default)]
pub struct Feed {
    changes: Vec<Change>,
}

impl Feed {
    pub fn new() -> Self {
        Feed::default()
    }

    /// The current cursor — the highest seq recorded (0 if empty).
    pub fn cursor(&self) -> u64 {
        self.changes.last().map(|c| c.seq).unwrap_or(0)
    }

    /// Record a change, assigning it the next seq. Returns the new cursor.
    pub fn record(&mut self, path: String, node_id: String, kind: ChangeKind, etag: String) -> u64 {
        let seq = self.cursor() + 1;
        self.changes.push(Change { seq, path, node_id, kind, etag });
        seq
    }

    /// Page of changes with `seq > cursor`, capped at `limit`. Returns `(changes, new_cursor)` where
    /// `new_cursor` is the seq of the last returned change (or `cursor` unchanged if none). Gap-free
    /// and resumable: re-`Poll` from `new_cursor`.
    pub fn poll(&self, cursor: u64, limit: u32) -> (Vec<Change>, u64) {
        let limit = limit.max(1) as usize;
        let page: Vec<Change> =
            self.changes.iter().filter(|c| c.seq > cursor).take(limit).cloned().collect();
        let new_cursor = page.last().map(|c| c.seq).unwrap_or(cursor);
        (page, new_cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> ChangeKind {
        ChangeKind::Created
    }

    #[test]
    fn cursor_advances_per_record() {
        let mut f = Feed::new();
        assert_eq!(f.cursor(), 0);
        assert_eq!(f.record("/a".into(), "n1".into(), k(), "e1".into()), 1);
        assert_eq!(f.record("/b".into(), "n2".into(), k(), "e2".into()), 2);
        assert_eq!(f.cursor(), 2);
    }

    #[test]
    fn poll_is_gap_free_and_resumable() {
        let mut f = Feed::new();
        for i in 0..5 {
            f.record(format!("/f{i}"), format!("n{i}"), k(), format!("e{i}"));
        }
        // First page of 2.
        let (page, cur) = f.poll(0, 2);
        assert_eq!(page.iter().map(|c| c.seq).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(cur, 2);
        // Resume from cursor 2 -> next 2.
        let (page, cur) = f.poll(cur, 2);
        assert_eq!(page.iter().map(|c| c.seq).collect::<Vec<_>>(), vec![3, 4]);
        assert_eq!(cur, 4);
        // And the tail.
        let (page, cur) = f.poll(cur, 2);
        assert_eq!(page.iter().map(|c| c.seq).collect::<Vec<_>>(), vec![5]);
        assert_eq!(cur, 5);
        // Nothing left: cursor unchanged.
        let (page, cur) = f.poll(cur, 2);
        assert!(page.is_empty());
        assert_eq!(cur, 5);
    }
}
