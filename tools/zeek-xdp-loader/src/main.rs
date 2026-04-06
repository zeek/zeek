mod maps;

use anyhow::Context as _;
use aya::EbpfLoader;
use aya::maps::{HashMap as BpfHashMap, MapData};
use aya::programs::links::PinnedLink;
use aya::programs::{Xdp, XdpFlags, links::FdLink};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

use std::fmt;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Parser)]
struct Opt {
    #[command(subcommand)]
    command: Commands,
    #[clap(long, default_value = "/sys/fs/bpf/zeek")]
    pin_path_prefix: String,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum MapTy {
    #[default]
    FlowMap,
    IpPairMap,
}

impl fmt::Display for MapTy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MapTy::FlowMap => write!(f, "flow-map"),
            MapTy::IpPairMap => write!(f, "ip-pair-map"),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum XdpMode {
    Native,
    Skb,
    Hw,
    #[default]
    Unspecified,
}

impl fmt::Display for XdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XdpMode::Native => write!(f, "native"),
            XdpMode::Skb => write!(f, "skb"),
            XdpMode::Hw => write!(f, "hw"),
            XdpMode::Unspecified => write!(f, "unspecified"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    Load {
        #[clap(short, long)]
        obj: String,
        #[clap(short, long)]
        iface: String,
        #[clap(short, long, default_value_t)]
        mode: XdpMode,
        #[clap(long, default_value_t = 65535)]
        flow_map_max_size: u32,
        #[clap(long, default_value_t = 65535)]
        ip_pair_map_max_size: u32,
    },
    Unload {
        #[clap(short, long)]
        iface: String,
    },
    Count {
        #[arg(long, value_enum, default_value_t)]
        map: MapTy,
    },
    Dump {
        #[arg(long, value_enum, default_value_t)]
        map: MapTy,
        #[arg(short, long)]
        json: bool,
    },
    Purge {
        #[arg(long, value_enum, default_value_t)]
        map: MapTy,
        #[clap(value_parser = |s: &str| s.parse().map(Duration::from_secs))]
        seconds: Duration,
        #[arg(short, long)]
        dry_run: bool,
    },
}

type ShuntMap<K> = BpfHashMap<MapData, K, maps::ShuntVal>;

fn load_command(
    obj: &str,
    pin_path: &Path,
    iface: &str,
    mode: XdpMode,
    flow_map_max_size: u32,
    ip_pair_map_max_size: u32,
) -> anyhow::Result<()> {
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(pin_path)
        .map_max_entries("filter_map", flow_map_max_size)
        .map_max_entries("ip_pair_map", ip_pair_map_max_size)
        .load_file(obj)?;

    let program: &mut Xdp = ebpf.program_mut("xdp_filter").unwrap().try_into()?;
    program.load()?;
    let mut flags = XdpFlags::default();
    match mode {
        XdpMode::Native => flags.insert(XdpFlags::DRV_MODE),
        XdpMode::Skb => flags.insert(XdpFlags::SKB_MODE),
        XdpMode::Hw => flags.insert(XdpFlags::HW_MODE),
        XdpMode::Unspecified => (),
    }
    let link_id = program
        .attach(iface, flags)
        .context("failed to attach the XDP program - try SKB mode instead")?;

    // Pin the link so that the program stays alive
    let link = program.take_link(link_id)?;
    let fd_link = FdLink::try_from(link).context("Hello")?;
    fd_link.pin(pin_path.join(iface))?;

    Ok(())
}

fn unload_command(pin_path: &Path, iface: &str) -> anyhow::Result<()> {
    PinnedLink::from_pin(pin_path.join(iface))?.unpin()?;

    Ok(())
}

fn dump_command_json<K>(map: ShuntMap<K>) -> anyhow::Result<()>
where
    K: aya::Pod + Serialize,
{
    let out: Vec<maps::MapEntry<K>> = map
        .iter()
        .map(|res| {
            let (key, val) = res?;
            Ok(maps::MapEntry { key, val })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let json_output = serde_json::to_string_pretty(&out)?;
    println!("{json_output}");

    Ok(())
}

fn dump_command_txt<K>(map: ShuntMap<K>) -> anyhow::Result<()>
where
    K: aya::Pod + fmt::Display,
{
    println!("Dumping map");
    for ele in map.iter() {
        let (key, val) = ele?;
        println!("Key: {key}");
        println!("Val: {val}");
        println!();
    }

    Ok(())
}

fn purge_command<K>(
    mut map: ShuntMap<K>,
    seconds: std::time::Duration,
    dry_run: bool,
) -> anyhow::Result<()>
where
    K: aya::Pod + fmt::Display,
{
    let now = Utc::now();
    let stale_entries: Vec<(K, DateTime<Utc>)> = map
        .iter()
        .filter_map(|key_val| {
            let (key, val) = key_val.ok()?;
            let last_packet_time = maps::datetime_from_timestamp(val.timestamp)?;
            (now > last_packet_time + seconds).then_some((key, last_packet_time))
        })
        .collect();

    let count = stale_entries.len();
    if dry_run {
        eprintln!("[DRY RUN]");
        eprintln!("{count} keys to be purged: ");
        stale_entries.iter().for_each(|(key, last_packet_time)| {
            eprintln!(
                "{}: Last packet {} seconds ago",
                key,
                (now - last_packet_time).num_seconds()
            );
        });
    } else {
        for (key, _) in stale_entries {
            let _ = map.remove(&key);
        }

        eprintln!("Purged {count} entries.");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let Opt {
        command,
        pin_path_prefix,
    } = opt;
    let pin_path = Path::new(&pin_path_prefix);

    match command {
        Commands::Load {
            obj,
            iface,
            mode,
            flow_map_max_size,
            ip_pair_map_max_size,
        } => {
            // May need to create the directory
            std::fs::create_dir_all(pin_path)?;

            load_command(
                &obj,
                pin_path,
                &iface,
                mode,
                flow_map_max_size,
                ip_pair_map_max_size,
            )?;
        }
        Commands::Unload { iface } => {
            unload_command(pin_path, &iface)?;
        }
        // Just counts the entries in the map for debugging
        Commands::Count { map } => {
            let count = match map {
                MapTy::FlowMap => maps::get_filter_map(pin_path)?.iter().count(),
                MapTy::IpPairMap => maps::get_ip_pair_map(pin_path)?.iter().count(),
            };

            println!("Found {} entries in map.", count)
        }
        // Dumps the map
        Commands::Dump { map, json } => {
            match map {
                MapTy::FlowMap => {
                    if json {
                        dump_command_json(maps::get_filter_map(pin_path)?)?;
                    } else {
                        dump_command_txt(maps::get_filter_map(pin_path)?)?;
                    }
                }
                MapTy::IpPairMap => {
                    if json {
                        dump_command_json(maps::get_ip_pair_map(pin_path)?)?;
                    } else {
                        dump_command_txt(maps::get_ip_pair_map(pin_path)?)?;
                    }
                }
            };
        }
        Commands::Purge {
            map,
            seconds,
            dry_run,
        } => {
            match map {
                MapTy::FlowMap => purge_command(maps::get_filter_map(pin_path)?, seconds, dry_run)?,
                MapTy::IpPairMap => {
                    purge_command(maps::get_ip_pair_map(pin_path)?, seconds, dry_run)?
                }
            };
        }
    }

    Ok(())
}
