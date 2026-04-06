use aya::Pod;
use aya::maps::{HashMap, Map, MapData};
use chrono::{DateTime, Utc};
use nix::time::{ClockId, clock_gettime};
use serde::{Serialize, Serializer};

use std::fmt;
use std::net::Ipv6Addr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn format_ip(bytes: [u8; 16]) -> String {
    let ipv6 = Ipv6Addr::from(bytes);
    if let Some(ipv4) = ipv6.to_ipv4_mapped() {
        ipv4.to_string()
    } else {
        ipv6.to_string()
    }
}

fn serialize_ip<S>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(format_ip(*bytes).as_str())
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize)]
pub struct CanonicalTuple {
    #[serde(serialize_with = "serialize_ip")]
    pub ip1: [u8; 16],
    #[serde(serialize_with = "serialize_ip")]
    pub ip2: [u8; 16],
    pub port1: u16,
    pub port2: u16,
    pub protocol: u16,
    pub outer_vlan_id: u16,
    pub inner_vlan_id: u16,
    #[serde(skip)]
    pub _padding: u16,
}

unsafe impl Pod for CanonicalTuple {}

impl fmt::Display for CanonicalTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip1 = format_ip(self.ip1);
        let ip2 = format_ip(self.ip2);

        write!(
            f,
            "[{ip1}]:{}<->[{ip2}]:{} (proto: {}, vlan: {}.{})",
            self.port1, self.port2, self.protocol, self.outer_vlan_id, self.inner_vlan_id
        )
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize)]
pub struct IPPair {
    #[serde(serialize_with = "serialize_ip")]
    pub ip1: [u8; 16],
    #[serde(serialize_with = "serialize_ip")]
    pub ip2: [u8; 16],
    pub outer_vlan_id: u16,
    pub inner_vlan_id: u16,
}

unsafe impl Pod for IPPair {}

impl fmt::Display for IPPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip1 = format_ip(self.ip1);
        let ip2 = format_ip(self.ip2);

        write!(
            f,
            "[{ip1}]<->[{ip2}] (vlan: {}.{})",
            self.outer_vlan_id, self.inner_vlan_id
        )
    }
}

#[derive(Serialize)]
pub struct MapEntry<K> {
    pub key: K,
    pub val: ShuntVal,
}

pub fn datetime_from_timestamp(timestamp: u64) -> Option<DateTime<Utc>> {
    let wall_clock_ns = get_boot_time_ns() + timestamp;
    DateTime::from_timestamp(
        (wall_clock_ns / 1_000_000_000) as i64,
        (wall_clock_ns % 1_000_000_000) as u32,
    )
}

fn format_timestamp(timestamp: u64) -> Option<String> {
    Some(
        datetime_from_timestamp(timestamp)?
            .format("%H:%M:%S%.3f")
            .to_string(),
    )
}

fn serialize_timestamp<S>(timestamp: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(datetime) = format_timestamp(*timestamp) {
        serializer.serialize_str(datetime.as_str())
    } else {
        serializer.serialize_str("")
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize)]
pub struct ShuntVal {
    pub lock_pad: u32,
    pub packets_from_1: u64,
    pub packets_from_2: u64,
    pub bytes_from_1: u64,
    pub bytes_from_2: u64,
    #[serde(serialize_with = "serialize_timestamp")]
    pub timestamp: u64,
}

unsafe impl Pod for ShuntVal {}

fn get_boot_time_ns() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos() as u64;

    let mono = clock_gettime(ClockId::CLOCK_MONOTONIC).expect("Failed to get monotonic time");
    let mono_ns = (mono.tv_sec() as u64 * 1_000_000_000) + mono.tv_nsec() as u64;

    now.saturating_sub(mono_ns)
}

impl fmt::Display for ShuntVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Last timestamp: {} | Packets: {}/{} | Bytes: {}/{}",
            format_timestamp(self.timestamp).unwrap_or("<NONE>".to_string()),
            self.packets_from_1,
            self.packets_from_2,
            self.bytes_from_1,
            self.bytes_from_2
        )
    }
}

pub const FILTER_MAP_NAME: &str = "filter_map";
pub const IP_PAIR_MAP_NAME: &str = "ip_pair_map";

fn get_shunt_map<KeyTy>(
    pin_path: &Path,
    map_name: &str,
) -> anyhow::Result<HashMap<MapData, KeyTy, ShuntVal>>
where
    KeyTy: Pod,
{
    let map_data = MapData::from_pin(pin_path.join(map_name))
        .map_err(|e| anyhow::anyhow!("Failed to load map from pin: {}", e))?;

    let raw_map = Map::HashMap(map_data);
    HashMap::try_from(raw_map)
        .map_err(|_| anyhow::anyhow!("Map is not a HashMap or types don't match"))
}

pub fn get_filter_map(
    pin_path: &Path,
) -> anyhow::Result<HashMap<MapData, CanonicalTuple, ShuntVal>> {
    get_shunt_map(pin_path, FILTER_MAP_NAME)
}

pub fn get_ip_pair_map(pin_path: &Path) -> anyhow::Result<HashMap<MapData, IPPair, ShuntVal>> {
    get_shunt_map(pin_path, IP_PAIR_MAP_NAME)
}
