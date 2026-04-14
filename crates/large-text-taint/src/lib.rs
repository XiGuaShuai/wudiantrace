//! ARM64 xgtrace taint tracking engine.
//!
//! Rust port of the gumtrace C++ project (TraceParser + TaintEngine).
//! Designed to consume an in-memory byte slice (e.g. an mmap from
//! `large-text-core::FileReader`) so callers do not have to re-open files.

pub mod engine;
pub mod parser;
pub mod reg;
pub mod trace;

pub use engine::{ResultEntry, StopReason, TaintEngine, TaintSource, TrackMode};
pub use parser::TraceParser;
pub use reg::{reg_name, RegId};
pub use trace::{InsnCategory, TraceLine};
