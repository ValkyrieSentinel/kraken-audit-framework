#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    programs::TcContext,
    maps::{HashMap, RingBuf},
    helpers::bpf_l3_csum_replace,
    EbpfContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StackEvent {
    pub port: u16,
    pub payload_sample: [u8; 16],
}

#[map]
static TARGET_IPS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static MAC_MAP: HashMap<u32, [u8; 6]> = HashMap::with_max_entries(1, 0);

#[map]
static REAL_MAC_MAP: HashMap<u32, [u8; 6]> = HashMap::with_max_entries(1, 0);

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[classifier]
pub fn kraken_ingress(ctx: TcContext) -> i32 {
    match try_kraken_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_kraken_ingress(mut ctx: TcContext) -> Result<i32, i64> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| -1i64)?;
    
    
    let eth_type = eth_hdr.ether_type;
    if eth_type != EtherType::Ipv4 { return Ok(0); }
    
    let ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| -1i64)?;
    let src_ip = ip_hdr.src_addr;

    if unsafe { TARGET_IPS.get(&src_ip) }.is_some() {
        if let Some(real_mac) = unsafe { REAL_MAC_MAP.get(&0) } {
            let mut eth_mut = eth_hdr;
            eth_mut.dst_addr = *real_mac;
            ctx.store(0, &eth_mut, 0).map_err(|_| -1i64)?;
        }
    }
    
    Ok(0)
}

#[classifier]
pub fn kraken_stealth(ctx: TcContext) -> i32 {
    match try_kraken_stealth(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, 
    }
}

fn try_kraken_stealth(mut ctx: TcContext) -> Result<i32, i64> {
    let eth_peek: EthHdr = ctx.load(0).map_err(|_| -1i64)?;
    
    let eth_type = eth_peek.ether_type;
    if eth_type != EtherType::Ipv4 { return Ok(0); }

    let ip_peek: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| -1i64)?;
    let dest_ip = ip_peek.dst_addr;

    if unsafe { TARGET_IPS.get(&dest_ip) }.is_none() {
        return Ok(0); 
    }

   
    let proto = ip_peek.proto;
    if proto != IpProto::Tcp { return Ok(0); }

    let tcp_peek: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| -1i64)?;
    let dest_port = u16::from_be(tcp_peek.dest);

    let target_mac = unsafe { MAC_MAP.get(&0).copied() }
        .unwrap_or([0x00, 0x0a, 0x27, 0x11, 0x22, 0x33]);
    
    let mut eth_hdr = eth_peek; 
    eth_hdr.src_addr = target_mac;
    ctx.store(0, &eth_hdr, 0).map_err(|_| -1i64)?;

    let mut ip_hdr = ip_peek;
    let old_ttl = ip_hdr.ttl;
    let new_ttl: u8 = 128; 
    
    if old_ttl != new_ttl {
        ip_hdr.ttl = new_ttl;
        unsafe {
            bpf_l3_csum_replace(
                ctx.as_ptr() as *mut _, 
                (10 + EthHdr::LEN) as u32, 
                old_ttl as u64, 
                new_ttl as u64, 
                core::mem::size_of::<u8>() as u64
            );
        }
        ctx.store(EthHdr::LEN, &ip_hdr, 0).map_err(|_| -1i64)?;
    }

    let len = ctx.len() as usize;
    let doff = (tcp_peek.doff() as usize) * 4;
    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + doff;
    
    if len >= payload_offset + 16 {
        if let Some(mut slot) = RING_BUF.reserve::<StackEvent>(0) {
            if let Ok(data) = ctx.load::<[u8; 16]>(payload_offset) {
                let event = unsafe { &mut *slot.as_mut_ptr() };
                event.port = dest_port;
                event.payload_sample = data;
                slot.submit(0);
            } else {
                slot.discard(0);
            }
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}