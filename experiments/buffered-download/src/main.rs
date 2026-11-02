// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Experimental real-NIC receive workload; deliberately outside the default Benchy suite.
#[cfg(not(target_os = "linux"))]
compile_error!("the buffered download experiment requires Linux");

mod batch;
mod outgoing;
mod packets;
mod run;
mod sink;
mod upload;
mod worker;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run(Run),
    Upload(Run),
    Drain(upload::DrainArgs),
    Endpoint(Endpoint),
    Sender(Sender),
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Direct,
    Gotatun,
}

#[derive(Args, Serialize)]
struct Run {
    #[arg(long, default_value = "mole@10.0.0.2")]
    peer: String,
    #[arg(long, default_value = "10.0.0.1")]
    alice: Ipv4Addr,
    #[arg(long, default_value = "10.0.0.2")]
    bob: Ipv4Addr,
    #[arg(long, default_value = "eno2")]
    nic: String,
    #[arg(long, default_value = "bgio0")]
    interface: String,
    #[arg(long, default_value_t=1_000_000, value_parser=clap::value_parser!(u32).range(1_000..=2_000_000))]
    packets: u32,
    #[arg(long, default_value_t=1200, value_parser=clap::value_parser!(u16).range(64..=1400))]
    payload: u16,
    #[arg(long, default_value_t=64, value_parser=clap::value_parser!(u16).range(1..=256))]
    batch: u16,
    /// Offered application-payload Gb/s. Zero means unpaced maximum.
    #[arg(long, value_delimiter = ',', default_value = "1,2,3,4,6,8,0")]
    rates: Vec<f64>,
    #[arg(long, value_delimiter = ',', default_value = "direct,gotatun")]
    modes: Vec<Mode>,
    #[arg(long, default_value_t=1, value_parser=clap::value_parser!(u16).range(1..=10))]
    repetitions: u16,
    /// Optional taskset CPU list for Alice's GotaTun process only.
    #[arg(long)]
    endpoint_cpus: Option<String>,
    /// Override the receive-buffer limit on Alice's owned GotaTun socket only.
    #[arg(long, default_value_t=0, value_parser=clap::value_parser!(u32).range(0..=64))]
    receive_buffer_mib: u32,
    #[arg(long, default_value = "buffered-io.json")]
    output: PathBuf,
}

#[derive(Args)]
struct Endpoint {
    #[arg(long)]
    send_report: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    data_wire_len: usize,
    #[arg(long, default_value_t = 0)]
    receive_buffer_mib: u32,
    #[arg(long)]
    private_key: String,
    #[arg(long)]
    peer_public_key: String,
    #[arg(long)]
    bind: SocketAddrV4,
    #[arg(long)]
    peer: SocketAddrV4,
    #[arg(long)]
    interface: String,
}

#[derive(Args)]
struct Sender {
    #[arg(long)]
    mode: Mode,
    #[arg(long)]
    private_key: String,
    #[arg(long)]
    peer_public_key: String,
    #[arg(long)]
    bind: SocketAddrV4,
    #[arg(long)]
    target: SocketAddrV4,
    #[arg(long)]
    control: SocketAddrV4,
    #[arg(long)]
    packets: u32,
    #[arg(long)]
    payload: u16,
    #[arg(long)]
    batch: u16,
    #[arg(long)]
    rate: f64,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Run(args) => run::run(args).await,
        Command::Upload(args) => upload::run(args).await,
        Command::Drain(args) => tokio::task::spawn_blocking(|| upload::drain(args)).await?,
        Command::Endpoint(args) => worker::endpoint(args).await,
        Command::Sender(args) => tokio::task::spawn_blocking(|| worker::sender(args)).await?,
    }
}
