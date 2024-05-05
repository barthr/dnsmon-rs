use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{exit, Command},
};

use libbpf_cargo::SkeletonBuilder;

const VMLINUX_FILE: &str = "src/bpf/vmlinux.h";
const SRC: &str = "src/bpf/dns.bpf.c";

fn binary_exists(binary_name: &str) -> bool {
    return Command::new("which")
        .arg(binary_name)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
}

fn main() {
    println!("cargo::rerun-if-changed={SRC}");

    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("dns.skel.rs");

    let profile = std::env::var("PROFILE").expect("Expect PROFILE to be present");

    if !binary_exists("bpftool") {
        eprint!("Expected bpftool binary to be present, it is required to generate a correct vmlinux.h for your arch");
        exit(1);
    }

    let vmlinux_file = Path::new(VMLINUX_FILE);
    if !vmlinux_file.exists() {
        let command = vec![
            "bpftool",
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ];

        Command::new(&command[0])
            .args(&command[1..])
            .current_dir(env::current_dir().expect("Failed retrieving current_dir"))
            .output()
            .map(|output| String::from_utf8(output.stdout))
            .and_then(|body| fs::write(vmlinux_file, body.unwrap()))
            .expect("Expected bpftool (if present) to generate a vmlinux.h if it wasn't already present");
    }

    let flags = if profile.eq_ignore_ascii_case("release") {
        [OsStr::new("-D RELEASE")]
    } else {
        [OsStr::new("-D DEBUG")]
    };

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(flags)
        .build_and_generate(&out)
        .unwrap();
}
