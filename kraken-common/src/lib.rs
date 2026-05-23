#![no_std]

#[cfg(feature = "user")]
use serde::{Serialize, Deserialize};

pub const MAC_MAP_KEY: u32 = 0;
pub type MacAddress = [u8; 6];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub port: u16,
    pub action: u32, 
}

#[cfg_attr(feature = "user", derive(Serialize, Deserialize, Debug))]
#[derive(Clone, Copy)] 
#[repr(C)]
pub struct AuditData {
    pub port: u16,
    pub entropy: f32,
    pub has_leaks: u8, // 1 - true, 0 - false
    pub response_time: u32,
}


#[repr(C)]
#[derive(Clone, Copy)]
pub struct StackEvent {
    pub port: u16,
    pub payload_sample: [u8; 16],
}


#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for AuditData {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for StackEvent {}