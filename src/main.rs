use std::{
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::sleep,
    time::{Duration, Instant},
};

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Error, ErrorExt, RingBufferBuilder, TcHookBuilder, TC_EGRESS,
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

fn main() -> Result<(), Error> {
    let mut skel_builder = DnsSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let open_skel = skel_builder.open()?;

    let skel = open_skel.load().expect("Expected to load the DNS skeleton");
    let progs = skel.progs();
    let maps = skel.maps();

    let ifindex =
        iface_name_to_index("enp0s13f0u1u6").expect("Expected interface name to have an index");

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
        ringbuffer
            .poll(Duration::from_millis(100))
            .expect("Failed polling ringbuffer");
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
