// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Profiling harness that records a gotatun tunnel with dial9.
//!
//! The binary has three modes. `run` executes on the benchmark controller host: it builds an
//! ephemeral WireGuard pair with the peer machine, starts the profiled tunnel here through
//! sudo, and leaves dial9 trace segments on disk for upload. `endpoint` is the plain far-side
//! tunnel spawned on the peer over ssh. `tunnel` is the profiled near side, run as root by
//! `run`, which owns the dial9 recorder and the iperf workload.

mod controller;
mod endpoint;
mod tracing_events;
mod tunnel;
mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Profile a gotatun tunnel with dial9", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build an ephemeral WireGuard pair with the peer machine, run the profiled
    /// tunnel here, and produce dial9 trace segments.
    Run(controller::RunArgs),
    /// Plain far-side tunnel endpoint, spawned on the peer machine over ssh.
    Endpoint(endpoint::EndpointArgs),
    /// Profiled near-side tunnel, run as root by `gotatun-dial9 run` through sudo.
    Tunnel(tunnel::TunnelArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => controller::run(args),
        Commands::Endpoint(args) => endpoint::run(args),
        Commands::Tunnel(args) => tunnel::run(args),
    }
}
