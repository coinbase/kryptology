//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Commands {
    #[structopt(short, long, parse(from_os_str), default_value = ".spdx.yml")]
    pub config_file: PathBuf,
    #[structopt(long)]
    pub copyright: Option<String>,
    #[structopt(short, long)]
    pub ignore: Option<Vec<String>>,
    #[structopt(long)]
    pub license: Option<String>,
    #[structopt(name = "DIR", parse(from_os_str), default_value = ".")]
    pub starting_directory: PathBuf,
}
