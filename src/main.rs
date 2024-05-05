use std::{
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::sleep,
    time::Duration,
};

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Error, ErrorExt, TcHookBuilder, TC_INGRESS,
};

use crate::dns::DnsSkelBuilder;

mod dns {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/dns.skel.rs"));
}

fn main() -> Result<(), Error> {
    let mut skel_builder = DnsSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let open_skel = skel_builder.open()?;

    let skel = open_skel.load().expect("Expected to load the DNS skeleton");
    let progs = skel.progs();
    // Set up and attach ingress TC hook
    let mut ingress = TcHookBuilder::new(progs.dns().as_fd())
        .ifindex(2)
        .replace(true)
        .handle(1)
        .priority(1)
        .hook(TC_INGRESS);

    ingress
        .create()
        .context("Failed to create ingress TC qdisc")?;

    ingress
        .attach()
        .context("Failed to attach ingress TC prog")?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to handle CTRL-C");

    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0));
    }

    if let Err(e) = ingress.detach() {
        eprintln!("Failed to detach prog: {e}");
    }
    if let Err(e) = ingress.destroy() {
        eprintln!("Failed to destroy TC hook: {e}");
    }

    Ok(())
}
