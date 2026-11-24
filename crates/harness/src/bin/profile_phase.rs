//! Phase-isolated profiling driver for an external sampler.
//!
//! The untimed phases run before the readiness marker, and the phase itself
//! runs only after the caller creates the go file. An external sampler can
//! therefore attach between the two and collect samples for one phase.

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use harness::{systems, BoxError, ProofBox, System};

const USAGE: &str = "\
usage: profile_phase --system NAME --rounds R --phase setup|prove|verify [options]

options:
  --repeat N            phase calls inside the profiled window (default 1)
  --warmup N            unprofiled phase calls before READY (default 1)
  --go-file PATH        wait until PATH exists before running the phase
  -h, --help            print this help";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Setup,
    Prove,
    Verify,
}

impl Phase {
    fn parse(text: &str) -> Result<Self, String> {
        match text {
            "setup" => Ok(Self::Setup),
            "prove" => Ok(Self::Prove),
            "verify" => Ok(Self::Verify),
            other => Err(format!("unknown phase: {other}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Prove => "prove",
            Self::Verify => "verify",
        }
    }
}

struct Config {
    system: String,
    rounds: usize,
    phase: Phase,
    repeat: usize,
    warmup: usize,
    go_file: PathBuf,
}

fn main() -> ExitCode {
    let config = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        args => match parse_args(args) {
            Ok(Some(config)) => config,
            Ok(None) => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            Err(message) => {
                eprintln!("error: {message}");
                eprintln!("{USAGE}");
                return ExitCode::FAILURE;
            }
        },
    };

    match run(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args(args: &[String]) -> Result<Option<Config>, String> {
    let mut system = None;
    let mut rounds: Option<usize> = None;
    let mut phase = None;
    let mut repeat: usize = 1;
    let mut warmup: usize = 1;
    let mut go_file = PathBuf::from(".profile-go");

    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = |index: &mut usize| -> Result<&str, String> {
            *index += 1;
            args.get(*index)
                .map(String::as_str)
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag {
            "-h" | "--help" => return Ok(None),
            "--system" => system = Some(value(&mut index)?.to_string()),
            "--rounds" => {
                let text = value(&mut index)?;
                rounds = Some(
                    text.parse()
                        .map_err(|_| format!("invalid rounds: {text}"))?,
                );
            }
            "--phase" => phase = Some(Phase::parse(value(&mut index)?)?),
            "--repeat" => {
                let text = value(&mut index)?;
                repeat = text
                    .parse()
                    .map_err(|_| format!("invalid repeat: {text}"))?;
            }
            "--warmup" => {
                let text = value(&mut index)?;
                warmup = text
                    .parse()
                    .map_err(|_| format!("invalid warmup: {text}"))?;
            }
            "--go-file" => go_file = PathBuf::from(value(&mut index)?),
            other => return Err(format!("unknown option: {other}")),
        }
        index += 1;
    }

    let rounds = rounds.ok_or("--rounds is required")?;
    if rounds == 0 || !rounds.is_power_of_two() || rounds > mimc::MAX_ROUNDS {
        return Err(format!(
            "round count must be a power of two in 1..={}",
            mimc::MAX_ROUNDS
        ));
    }
    if repeat == 0 {
        return Err("repeat must be at least 1".to_string());
    }

    Ok(Some(Config {
        system: system.ok_or("--system is required")?,
        rounds,
        phase: phase.ok_or("--phase is required")?,
        repeat,
        warmup,
        go_file,
    }))
}

fn run(config: &Config) -> Result<(), BoxError> {
    let mut system = systems()
        .into_iter()
        .find(|system| system.name() == config.system)
        .ok_or_else(|| -> BoxError { format!("unknown system: {}", config.system).into() })?;

    system.prepare_universal(config.rounds)?;
    system.prepare(config.rounds)?;
    system.prepare_instance(config.rounds, 0)?;

    if config.phase == Phase::Setup && !system.has_setup() {
        return Err("system has no setup phase".into());
    }

    let mut proof = None;
    if config.phase != Phase::Setup && system.has_setup() {
        system.setup()?;
    }
    if config.phase == Phase::Verify {
        proof = Some(system.prove()?);
    }

    eprintln!(
        "system {} field {} r={} phase {} repeat {} warmup {}",
        system.name(),
        system.field(),
        config.rounds,
        config.phase.as_str(),
        config.repeat,
        config.warmup
    );

    for _ in 0..config.warmup {
        run_phase(&mut *system, config, &mut proof)?;
    }

    println!("READY");
    io::stdout().flush()?;
    while !config.go_file.exists() {
        thread::sleep(Duration::from_millis(5));
    }

    let start = Instant::now();
    run_phase(&mut *system, config, &mut proof)?;
    let elapsed = start.elapsed();
    println!(
        "DONE total_ns={} per_call_ns={} repeat={}",
        elapsed.as_nanos(),
        elapsed.as_nanos() / config.repeat as u128,
        config.repeat
    );
    Ok(())
}

fn run_phase(
    system: &mut dyn System,
    config: &Config,
    proof: &mut Option<ProofBox>,
) -> Result<(), BoxError> {
    match config.phase {
        Phase::Setup => {
            for _ in 0..config.repeat {
                system.setup()?;
            }
        }
        Phase::Prove => {
            // The statement is prepared before READY; repeating it keeps the
            // whole sampled window inside the timed phase.
            for _ in 0..config.repeat {
                std::hint::black_box(system.prove()?);
            }
        }
        Phase::Verify => {
            let proof = proof
                .as_ref()
                .ok_or_else(|| -> BoxError { "verify needs a proof".into() })?;
            for _ in 0..config.repeat {
                if !system.verify(proof)? {
                    return Err("proof did not verify".into());
                }
            }
        }
    }
    Ok(())
}
