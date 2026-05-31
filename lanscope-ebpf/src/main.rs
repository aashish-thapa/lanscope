//! lanscope XDP data path.
//!
//! Attached to the LAN-facing interface, this program does the cheap, hot-path
//! work and hands everything else to userspace:
//!   * accumulates per-flow counters in [`FLOWS`] (a 5-tuple `HashMap`),
//!   * emits a bounded [`Event`] to the [`EVENTS`] ring buffer for ARP and for
//!     UDP discovery protocols (DHCP / mDNS / SSDP), and
//!   * emits a one-shot `NewHost` event the first time each MAC is seen.
//!
//! It is strictly passive: every path returns `XDP_PASS`.
#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_ktime_get_ns, bpf_xdp_load_bytes},
    macros::{map, xdp},
    maps::{HashMap, LruHashMap, RingBuf},
    programs::XdpContext,
};
use lanscope_common::{Event, EventKind, FlowKey, FlowStats, MacAddr};

#[map]
static FLOWS: HashMap<FlowKey, FlowStats> = HashMap::with_max_entries(10_240, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracks which MACs we've already announced, so `NewHost` fires once each.
#[map]
static SEEN: LruHashMap<MacAddr, u8> = LruHashMap::with_max_entries(4096, 0);

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Max bytes of L4 payload copied into an [`Event`] (≤ EVENT_PAYLOAD_LEN).
const COPY_LEN: usize = 256;

#[xdp]
pub fn lanscope(ctx: XdpContext) -> u32 {
    // Never let an internal error affect forwarding: default to PASS.
    let _ = try_lanscope(&ctx);
    xdp_action::XDP_PASS
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn load_u8(ctx: &XdpContext, off: usize) -> Result<u8, ()> {
    Ok(unsafe { *ptr_at::<u8>(ctx, off)? })
}

#[inline(always)]
fn load_u16_be(ctx: &XdpContext, off: usize) -> Result<u16, ()> {
    let hi = load_u8(ctx, off)? as u16;
    let lo = load_u8(ctx, off + 1)? as u16;
    Ok((hi << 8) | lo)
}

#[inline(always)]
fn load_u32_be(ctx: &XdpContext, off: usize) -> Result<u32, ()> {
    let a = load_u8(ctx, off)? as u32;
    let b = load_u8(ctx, off + 1)? as u32;
    let c = load_u8(ctx, off + 2)? as u32;
    let d = load_u8(ctx, off + 3)? as u32;
    Ok((a << 24) | (b << 16) | (c << 8) | d)
}

#[inline(always)]
fn load_mac(ctx: &XdpContext, off: usize) -> Result<MacAddr, ()> {
    Ok(unsafe { *ptr_at::<MacAddr>(ctx, off)? })
}

#[inline(always)]
fn try_lanscope(ctx: &XdpContext) -> Result<(), ()> {
    let src_mac = load_mac(ctx, 6)?; // Ethernet source address
    let ethertype = load_u16_be(ctx, 12)?;

    announce_new_host(ctx, src_mac);

    match ethertype {
        ETH_P_ARP => {
            emit(ctx, EventKind::Arp, src_mac, 0, None);
        }
        ETH_P_IP => handle_ipv4(ctx, src_mac)?,
        _ => {}
    }
    Ok(())
}

/// Emit a `NewHost` event the first time we ever see `mac`.
#[inline(always)]
fn announce_new_host(ctx: &XdpContext, mac: MacAddr) {
    if unsafe { SEEN.get(&mac) }.is_none() {
        let _ = SEEN.insert(&mac, &1, 0);
        emit(ctx, EventKind::NewHost, mac, 0, None);
    }
}

#[inline(always)]
fn handle_ipv4(ctx: &XdpContext, src_mac: MacAddr) -> Result<(), ()> {
    let ver_ihl = load_u8(ctx, ETH_HDR_LEN)?;
    let ihl = ((ver_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Err(());
    }
    let total_len = load_u16_be(ctx, ETH_HDR_LEN + 2)? as u64;
    let proto = load_u8(ctx, ETH_HDR_LEN + 9)?;
    let src_ip = load_u32_be(ctx, ETH_HDR_LEN + 12)?;
    let dst_ip = load_u32_be(ctx, ETH_HDR_LEN + 16)?;

    // The L4 header sits at a *variable* offset (after the IP options), which the
    // verifier can't follow through per-byte direct packet reads. Copy a fixed
    // slice via the kernel helper and parse it from the (verifier-friendly) stack.
    let l4 = ETH_HDR_LEN + ihl;
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    let mut tcp_flags = 0u8;

    match proto {
        IPPROTO_TCP => {
            let mut hdr = [0u8; 16];
            if unsafe { bpf_xdp_load_bytes(ctx.ctx, l4 as u32, hdr.as_mut_ptr().cast(), 16) } == 0 {
                src_port = u16::from_be_bytes([hdr[0], hdr[1]]);
                dst_port = u16::from_be_bytes([hdr[2], hdr[3]]);
                tcp_flags = hdr[13];
            }
        }
        IPPROTO_UDP => {
            let mut hdr = [0u8; 8];
            if unsafe { bpf_xdp_load_bytes(ctx.ctx, l4 as u32, hdr.as_mut_ptr().cast(), 8) } == 0 {
                src_port = u16::from_be_bytes([hdr[0], hdr[1]]);
                dst_port = u16::from_be_bytes([hdr[2], hdr[3]]);
            }
            if let Some(kind) = udp_discovery_kind(src_port, dst_port) {
                emit(ctx, kind, src_mac, src_ip, Some(l4 + 8)); // skip 8-byte UDP header
            }
        }
        _ => {}
    }

    update_flow(
        FlowKey::new(src_ip, dst_ip, src_port, dst_port, proto),
        total_len,
        tcp_flags,
    );
    Ok(())
}

/// Map UDP ports to a discovery [`EventKind`], if any.
#[inline(always)]
fn udp_discovery_kind(src: u16, dst: u16) -> Option<EventKind> {
    let p = |port: u16| src == port || dst == port;
    if p(67) || p(68) {
        Some(EventKind::Dhcp)
    } else if p(5353) {
        Some(EventKind::Mdns)
    } else if p(1900) {
        Some(EventKind::Ssdp)
    } else {
        None
    }
}

/// Accumulate counters for one packet into the flow table.
#[inline(always)]
fn update_flow(key: FlowKey, pkt_len: u64, tcp_flags: u8) {
    let now = unsafe { bpf_ktime_get_ns() };
    let len16 = if pkt_len > u16::MAX as u64 {
        u16::MAX
    } else {
        pkt_len as u16
    };

    if let Some(stats) = FLOWS.get_ptr_mut(&key) {
        unsafe {
            (*stats).packets += 1;
            (*stats).bytes += pkt_len;
            (*stats).last_seen_ns = now;
            if len16 < (*stats).min_len {
                (*stats).min_len = len16;
            }
            if len16 > (*stats).max_len {
                (*stats).max_len = len16;
            }
            accumulate_flags(&mut *stats, tcp_flags);
        }
    } else {
        let mut stats = FlowStats {
            packets: 1,
            bytes: pkt_len,
            first_seen_ns: now,
            last_seen_ns: now,
            min_len: len16,
            max_len: len16,
            ..Default::default()
        };
        accumulate_flags(&mut stats, tcp_flags);
        let _ = FLOWS.insert(&key, &stats, 0);
    }
}

#[inline(always)]
fn accumulate_flags(stats: &mut FlowStats, tcp_flags: u8) {
    if tcp_flags & 0x02 != 0 {
        stats.syn += 1;
    }
    if tcp_flags & 0x01 != 0 {
        stats.fin += 1;
    }
    if tcp_flags & 0x04 != 0 {
        stats.rst += 1;
    }
    if tcp_flags & 0x10 != 0 {
        stats.ack += 1;
    }
}

/// Reserve a ring-buffer slot and fill it directly (the [`Event`] is larger than
/// the eBPF stack allows, so we never build one on the stack).
#[inline(always)]
fn emit(ctx: &XdpContext, kind: EventKind, mac: MacAddr, src_ip: u32, payload_off: Option<usize>) {
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        return;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).kind = kind as u8;
        (*ev)._pad = [0; 1];
        (*ev).src_ip = src_ip;
        (*ev).src_mac = mac;
        (*ev)._pad2 = [0; 2];

        // Copy the payload with the kernel helper rather than hand-rolled direct
        // packet access: it does its own bounds checking, so the verifier doesn't
        // have to track packet-pointer ranges across a variable-length copy.
        let mut copied: u32 = 0;
        if let Some(off) = payload_off {
            let data = ctx.data();
            let data_end = ctx.data_end();
            if data_end > data + off {
                let avail = data_end - (data + off);
                let to_copy = if avail > COPY_LEN { COPY_LEN } else { avail } as u32;
                if to_copy > 0 {
                    let base = core::ptr::addr_of_mut!((*ev).payload) as *mut u8;
                    if bpf_xdp_load_bytes(ctx.ctx, off as u32, base.cast(), to_copy) == 0 {
                        copied = to_copy;
                    }
                }
            }
        }
        (*ev).payload_len = copied as u16;
    }
    entry.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // A real self-jump: gives the verifier a terminating instruction and keeps
    // any (unreachable) panic path from falling through past the program's end.
    loop {}
}
