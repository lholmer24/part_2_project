//! Command-line front end for the benchmark harness.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use harness::{metadata_path, run_to_csv, sweep_rounds, write_run_metadata, RunConfig};

const USAGE: &str = "\
usage: harness [options]

options:
  --system NAME         benchmark only this system; repeatable
  --rounds R            round count to benchmark; repeatable
  --setup-samples N     timed setups per configuration (default 10)
  --samples N           timed prove/verify pairs per configuration (default 10)
  --warmup N            warm-up prove/verify pairs per configuration (default 1)
  --output PATH         CSV output path (default results/benchmarks/benchmarks.csv)
  -h, --help            print this help";

fn main() -> ExitCode {
    match parse_args(env::args().skip(1)) {
        Ok(None) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Some(config)) => execute(&config),
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn execute(config: &RunConfig) -> ExitCode {
    // The sidecar is written first, so an interrupted sweep still has a
    // metadata file that describes the partial CSV.
    let metadata = metadata_path(&config.output);
    if let Err(error) = write_run_metadata(&metadata, config) {
        eprintln!("cannot write {}: {error}", metadata.display());
        return ExitCode::FAILURE;
    }

    let summary = match run_to_csv(config) {
        Ok(summary) => summary,
        Err(error) => {
            eprintln!("harness failed: {error}");
            if config.output.exists() {
                eprintln!("partial CSV kept at {}", config.output.display());
            }
            return ExitCode::FAILURE;
        }
    };

    for failure in &summary.failures {
        eprintln!(
            "{} at {} rounds: {}",
            failure.system, failure.rounds, failure.message
        );
    }

    println!(
        "wrote {} rows to {} and metadata to {}",
        summary.records,
        config.output.display(),
        metadata.display()
    );
    ExitCode::SUCCESS
}

fn parse_args<I: Iterator<Item = String>>(mut args: I) -> Result<Option<RunConfig>, String> {
    let mut config = RunConfig {
        rounds: Vec::new(),
        ..RunConfig::default()
    };

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "-h" | "--help" => return Ok(None),
            "--system" => config.systems.push(value(&mut args, "--system")?),
            "--rounds" => {
                let text = value(&mut args, "--rounds")?;
                let rounds: usize = text
                    .parse()
                    .map_err(|_| format!("invalid round count: {text}"))?;
                if rounds == 0 || !rounds.is_power_of_two() || rounds > mimc::MAX_ROUNDS {
                    return Err(format!(
                        "round count must be a power of two in 1..={}: {rounds}",
                        mimc::MAX_ROUNDS
                    ));
                }
                config.rounds.push(rounds);
            }
            "--setup-samples" => {
                let text = value(&mut args, "--setup-samples")?;
                config.setup_samples = text
                    .parse()
                    .map_err(|_| format!("invalid setup sample count: {text}"))?;
                if config.setup_samples == 0 {
                    return Err("setup sample count must be at least 1".to_string());
                }
            }
            "--samples" => {
                let text = value(&mut args, "--samples")?;
                config.samples = text
                    .parse()
                    .map_err(|_| format!("invalid sample count: {text}"))?;
                if config.samples == 0 {
                    return Err("sample count must be at least 1".to_string());
                }
            }
            "--warmup" => {
                let text = value(&mut args, "--warmup")?;
                config.warmup = text
                    .parse()
                    .map_err(|_| format!("invalid warm-up count: {text}"))?;
            }
            "--output" => config.output = PathBuf::from(value(&mut args, "--output")?),
            other => return Err(format!("unknown option: {other}")),
        }
    }

    if config.rounds.is_empty() {
        config.rounds = sweep_rounds();
    }

    Ok(Some(config))
}

fn value<I: Iterator<Item = String>>(args: &mut I, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}
