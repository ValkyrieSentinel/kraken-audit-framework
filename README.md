# Kraken Audit Framework

Security auditing framework combining eBPF Traffic Control, entropy-based data leak detection, and anonymous Tor scanning with automated PDF reporting.

## Overview
Kraken is a full-stack security research tool that operates at the kernel level (eBPF TC) to intercept and modify network packets, performs cryptographic entropy analysis to detect sensitive data leaks, and generates professional audit reports. Designed for authorized security assessments and red team operations.

## Key Features
- eBPF Traffic Control: Kernel-level packet interception and MAC/TTL manipulation via SchedClassifier programs.
- Entropy Analysis: Shannon entropy calculation to detect high-entropy payloads indicating potential data exfiltration or encryption.
- Anonymous Scanning: Integrated Tor SOCKS5 tunneling for stealthy reconnaissance.
- Lock-free Telemetry: RingBuf communication between kernel and user-space for real-time event streaming.
- Automated Reporting: Professional PDF report generation with timestamped evidence tables.

## Architecture
- kraken-ebpf: Kernel-space TC programs (kraken_ingress, kraken_stealth) for packet modification.
- kraken-core: User-space orchestrator managing eBPF maps, Tor connections, and entropy analysis.
- pdf-generator: Report generation module using genpdf with structured evidence tables.
- proxy-checker: Standalone utility for validating SOCKS5 proxy connectivity.

## Build and Run

1. Prerequisites:
    Install Rust, cargo, and libpcap-dev. Ensure you have access to /dev/kmsg and CAP_NET_ADMIN.

2. Build eBPF:
    cargo build --release --target bpfel-unknown-none -Z build-std=core

3. Build User-space:
    cargo build --release

4. Run:
    sudo ./target/release/kraken-audit-framework

## Security Notice
This tool is intended strictly for authorized security assessments, penetration testing, and educational research. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.

## License
MIT. Part of the ValkyrieSentinel ecosystem.
