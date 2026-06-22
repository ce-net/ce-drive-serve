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

    #[test]
    fn empty_feed_polls_empty() {
        let f = Feed::new();
        assert_eq!(f.cursor(), 0);
        let (page, cur) = f.poll(0, 10);
        assert!(page.is_empty());
        assert_eq!(cur, 0);
        // Polling from a future cursor on an empty feed returns nothing and keeps the cursor.
        let (page, cur) = f.poll(99, 10);
        assert!(page.is_empty());
        assert_eq!(cur, 99);
    }

    #[test]
    fn limit_zero_is_clamped_to_one() {
        let mut f = Feed::new();
        f.record("/a".into(), "n".into(), k(), "e".into());
        f.record("/b".into(), "n".into(), k(), "e".into());
        // limit 0 must not return an empty page forever (that would stall sync); it clamps to 1.
        let (page, cur) = f.poll(0, 0);
        assert_eq!(page.len(), 1);
        assert_eq!(cur, 1);
    }

    #[test]
    fn poll_past_the_end_is_gap_free_noop() {
        let mut f = Feed::new();
        for i in 0..3 {
            f.record(format!("/f{i}"), "n".into(), k(), "e".into());
        }
        // Cursor at/after the tail returns nothing and is stable (resumable, no replay).
        let (page, cur) = f.poll(3, 100);
        assert!(page.is_empty());
        assert_eq!(cur, 3);
        let (page, cur) = f.poll(1000, 100);
        assert!(page.is_empty());
        assert_eq!(cur, 1000);
    }

    #[test]
    fn full_drain_in_one_page_when_limit_large() {
        let mut f = Feed::new();
        for i in 0..50 {
            f.record(format!("/f{i}"), "n".into(), k(), "e".into());
        }
        let (page, cur) = f.poll(0, u32::MAX);
        assert_eq!(page.len(), 50);
        assert_eq!(cur, 50);
        // Sequence numbers are contiguous and strictly increasing (no gaps, no dups).
        for (i, c) in page.iter().enumerate() {
            assert_eq!(c.seq, i as u64 + 1);
        }
    }

    #[test]
    fn paging_covers_every_change_exactly_once() {
        // Property-ish: paging the whole feed in small pages yields every seq exactly once, in order.
        let mut f = Feed::new();
        let n = 137;
        for i in 0..n {
            f.record(format!("/f{i}"), "n".into(), k(), "e".into());
        }
        let mut seen = Vec::new();
        let mut cursor = 0u64;
        loop {
            let (page, cur) = f.poll(cursor, 7);
            if page.is_empty() {
                break;
            }
            for c in &page {
                seen.push(c.seq);
            }
            cursor = cur;
        }
        let expected: Vec<u64> = (1..=n as u64).collect();
        assert_eq!(seen, expected, "gap-free, dup-free, in-order coverage");
    }

    #[test]
    fn change_kinds_preserved_in_feed() {
        let mut f = Feed::new();
        f.record("/a".into(), "n".into(), ChangeKind::Created, "e".into());
        f.record("/b".into(), "n".into(), ChangeKind::Modified, "e".into());
        f.record("/c".into(), "n".into(), ChangeKind::Deleted, "e".into());
        f.record("/d".into(), "n".into(), ChangeKind::Moved { from: "/x".into() }, "e".into());
        let (page, _) = f.poll(0, 100);
        assert_eq!(page[0].kind, ChangeKind::Created);
        assert_eq!(page[3].kind, ChangeKind::Moved { from: "/x".into() });
    }
}
