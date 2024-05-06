use std::{
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::{arg, command, Parser};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Error, ErrorExt, MapFlags, RingBufferBuilder, TcHookBuilder, TC_EGRESS,
};
use pnet::datalink;

use crate::dns::DnsSkelBuilder;

mod dns {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/dns.skel.rs"));
}

fn iface_name_to_index(name: &str) -> Option<u32> {
    return datalink::interfaces()
        .iter()
        .find(|iface| iface.name == name)
        .map(|iface| iface.index);
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the interface to listen on
    #[arg(short, long)]
    iface: String,
}

fn fnv1a_64(data: &[u8]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;

    let mut hash = FNV_OFFSET_BASIS;
    for ele in data {
        hash ^= u64::from(*ele);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn main() -> Result<(), Error> {
    let args = Args::parse();

    let mut skel_builder = DnsSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let open_skel = skel_builder.open()?;

    let skel = open_skel.load().expect("Expected to load the DNS skeleton");
    let progs = skel.progs();
    let maps = skel.maps();

    let ifindex =
        iface_name_to_index(&args.iface).expect("Expected interface name to have an index");

    println!("Hash {}", fnv1a_64(&[1, 1, 1]));

    /*     maps.blocklist_hostnames()
           .update(
               &[115, 116, 101, 115, 116, 46, 98, 46, 100, 101, 118, 0], // stest.b.dev (with null terminator)
               &[1],
               MapFlags::ANY,
           )
           .expect("Expected to add record to blocklist hostnames");
    */
    println!("Adding TC hook to iface {}", &args.iface);

    let mut egress = TcHookBuilder::new(progs.dns().as_fd())
        .ifindex(ifindex.try_into().unwrap())
        .replace(true)
        .handle(1)
        .priority(1)
        .hook(TC_EGRESS);

    egress
        .create()
        .context("Failed to create egress TC qdisc")?;

    egress.attach().context("Failed to attach egress TC prog")?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to handle CTRL-C");

    // Set up ringbuffer for listening to DNS hostnames
    let mut rbuf_builder = RingBufferBuilder::new();
    rbuf_builder
        .add(&maps.dns_events(), on_receive_hostname)
        .expect("Failed to add ringbuf");
    let ringbuffer = rbuf_builder.build().expect("Failed to build ringbuffer");

    while running.load(Ordering::SeqCst) {
        if let Err(e) = ringbuffer.poll(Duration::from_millis(100)) {
            eprintln!("Failed polling ringbuffer: {e}")
        }
    }

    if let Err(e) = egress.detach() {
        eprintln!("Failed to detach prog: {e}");
    }
    if let Err(e) = egress.destroy() {
        eprintln!("Failed to destroy TC hook: {e}");
    }

    Ok(())
}

fn on_receive_hostname(buffer: &[u8]) -> i32 {
    // The layout is as follows: 4 bytes for the pid and the remaining 255 bytes for the hostname
    match std::str::from_utf8(&buffer[3..]) {
        Ok(s) => {
            // Successfully converted to a string
            println!("Received hostname: {}", s);
        }
        Err(e) => {
            // Conversion failed due to invalid UTF-8 data
            println!("Error: {}", e);
        }
    }
    return 0;
}
