//! Device fingerprinting.
//!
//! M1 ships only OUI→vendor lookup (used by the registry). M3 adds the full
//! fingerprint engine that fuses OUI + DHCP + mDNS/SSDP + traffic profile into a
//! device-type/model guess behind a `Fingerprinter` trait.

pub mod engine;
pub mod oui;
pub mod rules;

pub use engine::{Category, Classification, Fingerprinter};
pub use rules::RuleFingerprinter;
