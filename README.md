# dnsmon-rs

dnsmon-rs is a tool written in Rust for monitoring malicious DNS calls made from processes on your computer. It utilizes eBPF (extended Berkeley Packet Filter) with libbpf and CO:RE (Compile Once: Run Everywhere) for cross platform and low-overhead monitoring.

## Features

- Monitors DNS requests made by processes running on your computer.
- Detects and logs suspicious or malicious DNS calls based on predefined blacklists or DNS blocklists (e.g., Pi-hole).
- Provides real-time insights into DNS activity, including the process making the request, the domain queried, and the response status.

## Installation

1. Clone the dnsmon-rs repository:

```bash
git clone https://github.com/barthr/dnsmon-rs.git
```

2. Ensure bpftool is installed (needed for vmlinux.h). Consult your distro's documentation on how to get bpftool installed
```bash
which bpftool
```

3. Build the tool
```bash
cargo build --release
```