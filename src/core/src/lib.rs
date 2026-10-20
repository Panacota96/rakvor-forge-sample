//! RV HashInv core library.
//!
//! The core does all the work and never prints: front-ends (CLI, GUI) call [`run::run`] and
//! render the [`events::Event`] stream it emits.
//!
//! ```text
//! input ──► hash (1–2 algorithms, one read) ──► analyzer ──► duplicates ──► reports
//!   └──────────────── every step appended to the hash-chained audit log ───────────┘
//! ```

pub mod analyzer;
pub mod audit;
pub mod env;
pub mod events;
pub mod hash;
pub mod i18n;
pub mod input;
pub mod report;
pub mod run;
pub mod time;
pub mod trust;

pub use events::Event;
pub use hash::HashAlgo;
pub use run::{RunConfig, RunSummary, run};

pub const TOOL_NAME: &str = "rv-hashinv";
/// Product version = version.txt (bumped by release-please). The crate versions in Cargo.toml stay fixed so a
/// release never changes Cargo.lock (CI builds with --locked).
pub const TOOL_VERSION: &str = env!("RV_VERSION");
