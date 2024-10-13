mod blocklist;
mod hash;
mod net;

use std::{
    os::fd::AsFd,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc,
    },
    thread,
    time::Duration,
};

use clap::{arg, command, Parser};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Error, ErrorExt, RingBufferBuilder, TcHookBuilder, TC_EGRESS,
};

use crate::{blocklist::Blocklist, dns::DnsSkelBuilder, net::NetInterface};

mod dns {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/dns.skel.rs"));
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the interface to listen on
    #[arg(short, long)]
    iface: String,

    #[arg(long)]
    files: Vec<String>,

    #[arg(long)]
    urls: Vec<String>,
}

fn main() -> Result<(), Error> {
    let args = Args::parse();

    println!("Files {:?}", args.files);

    let mut skel_builder = DnsSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let open_skel = skel_builder.open()?;

    let skel = open_skel.load().expect("Expected to load the DNS skeleton");
    let progs = skel.progs();
    let maps = skel.maps();
    let blocklist_dp = maps.bl_hostnames();

    let iface = NetInterface::from_name(&args.iface)
        .expect(&format!("Expected interface {} to be present", args.iface));

    let _file_blocklists: Result<Vec<Blocklist>, std::io::Error> = args
        .files
        .iter()
        .map(Path::new)
        .map(Blocklist::from_file)
        .collect();

    let fp = Path::new("./blocklist.txt");
    let blocklist = Blocklist::from_file(fp)
        .map_err(|err| err.with_context(|| format!("for path {}", fp.display())))
        .expect("Expected blocklist to be loaded from file");

    // bl.match_hostname("test");
    //
    // let hostname =
    //     BlockRule::parse("test.bfkr.dev").expect("Domain name test.bkfr.dev is not valid");

    blocklist
        .add_to_dataplane(blocklist_dp)
        .expect("Expected to add record to dataplane");

    /*     blocklist
           .update(&[], &hash_hostname(&hostname), MapFlags::ANY)
           .expect("Expected to add record to blocklist hostnames");
    */
    println!("Adding TC hook to iface {}", &args.iface);

    let mut egress = TcHookBuilder::new(progs.dns().as_fd())
        .ifindex(iface.index.try_into().unwrap())
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

    let (tx, rx) = std::sync::mpsc::channel();

    // Set up ringbuffer for listening to DNS hostnames
    let mut rbuf_builder = RingBufferBuilder::new();
    rbuf_builder
        .add(&maps.dns_events(), on_receive_hostname(tx))
        .expect("Failed to add ringbuf");
    let ringbuffer = rbuf_builder.build().expect("Failed to build ringbuffer");

    let mut log_buffer = RingBufferBuilder::new();
    log_buffer
        .add(&maps.log_output(), log_message)
        .expect("Failed to add ringbuf");
    let log_ringbuffer = log_buffer.build().expect("Failed to build ringbuffer");

    while running.load(Ordering::SeqCst) {
        if let Err(e) = log_ringbuffer.poll(Duration::from_millis(50)) {
            eprintln!("Failed polling log buffer: {e}")
        }
        // let received_hostname = rx.recv_timeout(Duration::from_millis(50));
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

fn log_message(buffer: &[u8]) -> i32 {
    match std::str::from_utf8(&buffer) {
        Ok(s) => {
            // Successfully converted to a string
            println!("[dataplane] {}", s);
        }
        Err(e) => {
            // Conversion failed due to invalid UTF-8 data
            println!("Error: {}", e);
        }
    }
    0
}

fn on_receive_hostname(match_channel: Sender<String>) -> Box<dyn FnMut(&[u8]) -> i32> {
    Box::new(move |buffer: &[u8]| -> i32 {
        let send_ch = match_channel.clone();
        // The layout is as follows: 4 bytes for the pid and the remaining 255 bytes for the hostname
        match std::str::from_utf8(&buffer[3..]) {
            Ok(s) => {
                println!("[dataplane] received hostname from dataplane: {}", s);
                let hostname = s.to_string();
                thread::spawn(move || {
                    // this will block until the previous message has been received
                    let _ = send_ch.send(hostname);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
        0
    })
}
