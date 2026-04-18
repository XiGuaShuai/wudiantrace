//! Semantic-origin tagging for taint sources.
//!
//! When a register or memory byte becomes tainted the engine can attach a
//! [`TagId`] that resolves, via [`TagTable`], to a [`TaintOrigin`] carrying
//! the human-readable source of that byte — an external-call return value,
//! a read-only memory region, a known payload string, or a user seed.
//!
//! Phase 1 (this module) treats tags as coarse per-register / per-address
//! labels — the boolean taint state remains the source of truth for
//! propagation and tags ride along. Phase 2 will split tags to a per-byte
//! granularity inside each register.
//!
//! The table lives in its own structure outside [`TraceLine`] so the
//! ~1 KB-per-line hot structure stays small.

use rustc_hash::FxHashMap;

/// Compact identifier for a semantic taint origin.
///
/// `TagId(0)` is reserved for "no specific origin"; any taint whose bit is
/// set but whose tag is 0 simply means the usual boolean taint without a
/// named source.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct TagId(pub u16);

pub const TAG_UNTAGGED: TagId = TagId(0);

impl TagId {
    #[inline]
    pub fn is_tagged(self) -> bool {
        self.0 != 0
    }
}

/// Description of where a taint byte semantically came from.
#[derive(Clone, Debug)]
pub enum TaintOrigin {
    /// Return value written to `x0` by a `-> libc.so!foo(...) ret: 0x...`
    /// line. The tag applies to `x0` at the ExternalCall line itself and
    /// propagates through subsequent instructions normally.
    ExternalCallRet {
        /// Parser line index (0-based) of the ExternalCall line.
        line_index: u32,
        /// Callee symbol, e.g. "libc.so!rand" or "_JNIEnv::GetStringUTFChars".
        callee: String,
        /// First ~80 chars of argument preview, free-form.
        args_preview: String,
        /// Return value written to `x0`.
        ret_val: u64,
    },

    /// A memory region that is read during the trace but never written —
    /// typically `.rodata`, the GOT, or linker-initialised data from
    /// whatever module the trace ran inside.
    ConstMem {
        addr_lo: u64,
        addr_hi: u64,
        module: Option<String>,
        offset: Option<u64>,
    },

    /// A payload string whose text was observed in the trace, e.g. the
    /// signature input buffer passed to `free(ptr=X="...")` or to
    /// `NewStringUTF`. Each byte in the range `[addr_lo, addr_lo +
    /// content.len())` maps to the corresponding byte of `content`.
    PayloadByte {
        payload_id: u32,
        addr_lo: u64,
        /// Raw bytes of the payload (truncated to [`PAYLOAD_PREVIEW_MAX`]
        /// for the origin record; the mapped range still covers the full
        /// observed length).
        content_preview: Vec<u8>,
        content_len: u32,
        /// Where the parser saw this payload: "free arg", "NewStringUTF",
        /// "GetStringUTFChars", …
        source_hint: String,
    },

    /// User-supplied seed from the taint-tracking dialog.
    UserSeed { label: String },
}

/// Cap the amount of preview text we keep per payload origin.
pub const PAYLOAD_PREVIEW_MAX: usize = 256;

impl TaintOrigin {
    /// A short, one-line rendering suitable for the taint snapshot UI.
    pub fn short_label(&self) -> String {
        match self {
            TaintOrigin::ExternalCallRet {
                callee, ret_val, ..
            } => format!("{}()→0x{:x}", callee, ret_val),
            TaintOrigin::ConstMem {
                module,
                offset,
                addr_lo,
                ..
            } => match (module.as_deref(), offset) {
                (Some(m), Some(o)) => format!("{}+0x{:x}", m, o),
                _ => format!("rodata@0x{:x}", addr_lo),
            },
            TaintOrigin::PayloadByte {
                payload_id,
                content_preview,
                ..
            } => {
                let text = String::from_utf8_lossy(content_preview);
                let snippet: String = text.chars().take(24).collect();
                format!("payload#{}:\"{}\"", payload_id, snippet.escape_default())
            }
            TaintOrigin::UserSeed { label } => format!("seed:{}", label),
        }
    }

    /// A longer rendering suitable for the boundary-taint section of the
    /// report or a dedicated "origins" panel.
    pub fn long_label(&self) -> String {
        match self {
            TaintOrigin::ExternalCallRet {
                line_index,
                callee,
                args_preview,
                ret_val,
            } => {
                if args_preview.is_empty() {
                    format!(
                        "{}() → 0x{:x}  [at trace index {}]",
                        callee, ret_val, line_index
                    )
                } else {
                    format!(
                        "{}({}) → 0x{:x}  [at trace index {}]",
                        callee, args_preview, ret_val, line_index
                    )
                }
            }
            TaintOrigin::ConstMem {
                addr_lo,
                addr_hi,
                module,
                offset,
            } => {
                let size = addr_hi.saturating_sub(*addr_lo);
                match (module, offset) {
                    (Some(m), Some(o)) => format!(
                        "const memory [0x{:x}..0x{:x}] ({} B) — {}+0x{:x}",
                        addr_lo, addr_hi, size, m, o
                    ),
                    _ => format!(
                        "const memory [0x{:x}..0x{:x}] ({} B) — read-only in trace",
                        addr_lo, addr_hi, size
                    ),
                }
            }
            TaintOrigin::PayloadByte {
                payload_id,
                addr_lo,
                content_preview,
                content_len,
                source_hint,
            } => {
                let text = String::from_utf8_lossy(content_preview);
                format!(
                    "payload #{} @ 0x{:x} ({} B, via {}): \"{}\"",
                    payload_id,
                    addr_lo,
                    content_len,
                    source_hint,
                    text.escape_default()
                )
            }
            TaintOrigin::UserSeed { label } => format!("user seed: {}", label),
        }
    }
}

/// Side-car table of all semantic tag origins for a parsed trace.
#[derive(Default)]
pub struct TagTable {
    origins: Vec<TaintOrigin>,
    /// ExternalCall line index → tag id for its return value.
    ext_call_tag: FxHashMap<u32, TagId>,
    /// Memory-range tags, sorted by `addr_lo` and non-overlapping.
    /// Holds both [`TaintOrigin::ConstMem`] and [`TaintOrigin::PayloadByte`]
    /// ranges; payloads take precedence over const-mem when a range overlap
    /// is encountered (payloads are more specific).
    mem_ranges: Vec<MemRangeTag>,
    /// Monotonic id for newly intern-ed payloads.
    next_payload_id: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct MemRangeTag {
    pub addr_lo: u64,
    /// Exclusive upper bound.
    pub addr_hi: u64,
    pub tag: TagId,
}

impl TagTable {
    pub fn new() -> Self {
        let mut t = Self {
            origins: Vec::new(),
            ext_call_tag: FxHashMap::default(),
            mem_ranges: Vec::new(),
            next_payload_id: 0,
        };
        // Index 0 is reserved as `TAG_UNTAGGED`.
        t.origins.push(TaintOrigin::UserSeed {
            label: "(untagged)".to_string(),
        });
        t
    }

    /// Intern an origin and return its new tag.
    pub fn intern(&mut self, origin: TaintOrigin) -> TagId {
        // The origins vec is bounded by 2^16 (u16 TagId). In practice Phase 1
        // creates one tag per external call + one per const range + one per
        // payload — even a 14M-line trace yields a few thousand tags — so
        // the saturation path is only a belt-and-braces fall-through.
        if self.origins.len() >= u16::MAX as usize {
            return TAG_UNTAGGED;
        }
        let id = TagId(self.origins.len() as u16);
        self.origins.push(origin);
        id
    }

    pub fn alloc_payload_id(&mut self) -> u32 {
        let id = self.next_payload_id;
        self.next_payload_id = self.next_payload_id.saturating_add(1);
        id
    }

    pub fn origin(&self, tag: TagId) -> Option<&TaintOrigin> {
        if tag == TAG_UNTAGGED {
            return None;
        }
        self.origins.get(tag.0 as usize)
    }

    pub fn origins_len(&self) -> usize {
        self.origins.len()
    }

    /// Iterate every origin paired with its `TagId`, skipping the reserved
    /// untagged slot.
    pub fn iter_origins(&self) -> impl Iterator<Item = (TagId, &TaintOrigin)> {
        self.origins
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, o)| (TagId(i as u16), o))
    }

    pub fn register_ext_call(&mut self, line_index: u32, origin: TaintOrigin) -> TagId {
        let tag = self.intern(origin);
        self.ext_call_tag.insert(line_index, tag);
        tag
    }

    /// Add a contiguous memory-range tag. If the new range overlaps
    /// existing ranges, it splits / shrinks as needed so the table stays
    /// sorted and non-overlapping; payload ranges take precedence over
    /// const ranges (we simply overwrite whatever was there).
    pub fn add_mem_range(&mut self, addr_lo: u64, addr_hi: u64, tag: TagId) {
        if addr_hi <= addr_lo || tag == TAG_UNTAGGED {
            return;
        }
        // Naive but simple: remove overlap, insert fresh, resort.
        // With a few thousand ranges this is cheap enough for Phase 1.
        self.mem_ranges
            .retain(|r| r.addr_hi <= addr_lo || r.addr_lo >= addr_hi);
        self.mem_ranges.push(MemRangeTag {
            addr_lo,
            addr_hi,
            tag,
        });
        self.mem_ranges.sort_by_key(|r| r.addr_lo);
    }

    pub fn tag_for_ext_call(&self, line_index: u32) -> Option<TagId> {
        self.ext_call_tag.get(&line_index).copied()
    }

    /// Binary-search a memory address against the sorted range table.
    pub fn tag_for_mem(&self, addr: u64) -> Option<TagId> {
        match self.mem_ranges.binary_search_by(|r| {
            if addr < r.addr_lo {
                std::cmp::Ordering::Greater
            } else if addr >= r.addr_hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(i) => Some(self.mem_ranges[i].tag),
            Err(_) => None,
        }
    }

    pub fn mem_ranges(&self) -> &[MemRangeTag] {
        &self.mem_ranges
    }

    pub fn ext_call_entries(&self) -> &FxHashMap<u32, TagId> {
        &self.ext_call_tag
    }
}

/// Merge two tags, preferring the more specific one.
///
/// Precedence (highest first):
///   UserSeed > PayloadByte > ExternalCallRet > ConstMem > Untagged
///
/// If both tags are different and of the same class, keep the left one
/// (first-seen wins). Phase 2 may promote conflicts to a synthesised
/// `Combined` tag, but Phase 1 keeps this function allocation-free.
pub fn merge_tags(table: &TagTable, a: TagId, b: TagId) -> TagId {
    if a == b {
        return a;
    }
    if a == TAG_UNTAGGED {
        return b;
    }
    if b == TAG_UNTAGGED {
        return a;
    }
    let rank_a = classify(table.origin(a));
    let rank_b = classify(table.origin(b));
    if rank_b > rank_a {
        b
    } else {
        a
    }
}

fn classify(o: Option<&TaintOrigin>) -> u8 {
    match o {
        None => 0,
        Some(TaintOrigin::ConstMem { .. }) => 1,
        Some(TaintOrigin::ExternalCallRet { .. }) => 2,
        Some(TaintOrigin::PayloadByte { .. }) => 3,
        Some(TaintOrigin::UserSeed { .. }) => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_and_lookup() {
        let mut t = TagTable::new();
        let a = t.intern(TaintOrigin::UserSeed {
            label: "x".into(),
        });
        let b = t.intern(TaintOrigin::ConstMem {
            addr_lo: 0x1000,
            addr_hi: 0x1010,
            module: None,
            offset: None,
        });
        assert_ne!(a, b);
        assert_ne!(a, TAG_UNTAGGED);
        assert!(matches!(
            t.origin(a).unwrap(),
            TaintOrigin::UserSeed { .. }
        ));
        assert!(matches!(
            t.origin(b).unwrap(),
            TaintOrigin::ConstMem { .. }
        ));
        assert!(t.origin(TAG_UNTAGGED).is_none());
    }

    #[test]
    fn mem_range_lookup() {
        let mut t = TagTable::new();
        let tag = t.intern(TaintOrigin::ConstMem {
            addr_lo: 0x2000,
            addr_hi: 0x2100,
            module: None,
            offset: None,
        });
        t.add_mem_range(0x2000, 0x2100, tag);
        assert_eq!(t.tag_for_mem(0x2000), Some(tag));
        assert_eq!(t.tag_for_mem(0x20ff), Some(tag));
        assert_eq!(t.tag_for_mem(0x2100), None);
        assert_eq!(t.tag_for_mem(0x1fff), None);
    }

    #[test]
    fn merge_prefers_specific() {
        let mut t = TagTable::new();
        let const_tag = t.intern(TaintOrigin::ConstMem {
            addr_lo: 0,
            addr_hi: 0,
            module: None,
            offset: None,
        });
        let payload_tag = t.intern(TaintOrigin::PayloadByte {
            payload_id: 0,
            addr_lo: 0,
            content_preview: vec![],
            content_len: 0,
            source_hint: "free".into(),
        });
        assert_eq!(merge_tags(&t, const_tag, payload_tag), payload_tag);
        assert_eq!(merge_tags(&t, payload_tag, TAG_UNTAGGED), payload_tag);
        assert_eq!(merge_tags(&t, const_tag, const_tag), const_tag);
    }
}
