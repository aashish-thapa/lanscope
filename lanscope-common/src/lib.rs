//! Plain-old-data types shared across the kernel/userspace boundary.
//!
//! Everything here is `#[repr(C)]` and free of pointers so the same bytes can
//! be written by an eBPF program (in a `HashMap` or `RingBuf`) and read back by
//! the userspace agent. The crate is `no_std` so the eBPF crate can depend on
//! it; userspace enables the `user` feature for `Display`/`std` conveniences.
#![cfg_attr(not(feature = "user"), no_std)]

pub mod event;
pub mod flow;

pub use event::{Event, EventKind, EVENT_PAYLOAD_LEN};
pub use flow::{FlowKey, FlowStats, Protocol};

// SAFETY: all three types are `#[repr(C)]`, contain only plain integers/arrays,
// and have no padding that aliases invalid bit patterns, so they are safe to
// reinterpret from raw eBPF map bytes.
#[cfg(feature = "aya-pod")]
mod pod {
    unsafe impl aya::Pod for crate::FlowKey {}
    unsafe impl aya::Pod for crate::FlowStats {}
    unsafe impl aya::Pod for crate::Event {}
}

/// A 48-bit hardware address. `[0u8; 6]` is treated as "unknown".
pub type MacAddr = [u8; 6];

/// IPv4 address in network byte order, as seen on the wire.
///
/// M1 is IPv4-only for discovery; IPv6 support is tracked for a later milestone
/// (the wire layout here would gain a parallel `Ipv6Addr` variant).
pub type Ipv4Be = u32;
