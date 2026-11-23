//! Benchmark harness for the MiMC preimage statement.
//!
//! `run_systems` times setup, prove and verify at one call boundary; adapters
//! must not hold timers. The CSV has one row per timed sample.

pub mod placeholder;
pub mod systems;

use std::any::Any;
use std::error::Error as StdError;
use std::fmt;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use placeholder::PlaceholderSystem;
pub use systems::{
    BulletproofsSystem, Groth16System, Halo2System, PlonkSystem, SpartanSystem, StarkSystem,
};

pub type BoxError = Box<dyn StdError + Send + Sync>;

pub const DEFAULT_SETUP_SAMPLES: usize = 10;

pub const DEFAULT_SAMPLES: usize = 10;

pub const DEFAULT_WARMUP: usize = 1;

pub const RESULTS_DIR: &str = "results";

pub const CSV_HEADER: &str = "system,field,rounds,phase,sample,time_ns,proof_size_bytes";

pub const BENCHMARK_SEED_DOMAIN: &[u8] = b"mimc-benchmark-v1";

pub fn benchmark_seed(rounds: usize, instance: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BENCHMARK_SEED_DOMAIN);
    hasher.update(&(rounds as u64).to_le_bytes());
    hasher.update(&(instance as u64).to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Setup,
    Prove,
    Verify,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Prove => "prove",
            Self::Verify => "verify",
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub system: String,
    pub field: String,
    pub rounds: usize,
    pub phase: Phase,
    pub sample: usize,
    pub time: Duration,
    pub proof_size_bytes: Option<usize>,
}

pub struct ProofBox(Box<dyn Any>);

impl ProofBox {
    pub fn new<T: Any>(proof: T) -> Self {
        Self(Box::new(proof))
    }

    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub system: String,
    pub rounds: usize,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct SweepResult {
    pub records: Vec<Record>,
    pub failures: Vec<Failure>,
}

pub trait System {
    fn name(&self) -> &str;

    fn field(&self) -> &str;

    /// Untimed, once per system before the sweep.
    fn prepare_universal(&mut self, _max_rounds: usize) -> Result<(), BoxError> {
        Ok(())
    }

    /// Untimed, once per configuration.
    fn prepare(&mut self, _rounds: usize) -> Result<(), BoxError> {
        Ok(())
    }

    /// Untimed, before every warm-up and timed proof. Must keep setup keys and
    /// universal parameters intact.
    fn prepare_instance(&mut self, _rounds: usize, _instance: usize) -> Result<(), BoxError> {
        Ok(())
    }

    fn has_setup(&self) -> bool {
        true
    }

    fn setup(&mut self) -> Result<(), BoxError>;

    fn prove(&self) -> Result<ProofBox, BoxError>;

    fn proof_size(&self, proof: &ProofBox) -> Result<usize, BoxError>;

    fn verify(&self, proof: &ProofBox) -> Result<bool, BoxError>;
}

#[derive(Clone, Debug)]
pub struct RunConfig {
    /// Empty means every registered system.
    pub systems: Vec<String>,
    /// Empty means [`sweep_rounds`].
    pub rounds: Vec<usize>,
    pub setup_samples: usize,
    pub samples: usize,
    pub warmup: usize,
    pub output: PathBuf,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            systems: Vec::new(),
            rounds: Vec::new(),
            setup_samples: DEFAULT_SETUP_SAMPLES,
            samples: DEFAULT_SAMPLES,
            warmup: DEFAULT_WARMUP,
            output: default_output_path(),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidConfig(String),
    UnknownSystem(String),
    NoSystems,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "harness I/O error: {error}"),
            Self::Json(error) => write!(f, "metadata JSON error: {error}"),
            Self::InvalidConfig(message) => write!(f, "invalid configuration: {message}"),
            Self::UnknownSystem(name) => write!(f, "unknown system: {name}"),
            Self::NoSystems => write!(f, "no system matched the configuration"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub fn sweep_rounds() -> Vec<usize> {
    (0..=mimc::MAX_ROUNDS.trailing_zeros())
        .map(|k| 1usize << k)
        .collect()
}

pub fn default_output_path() -> PathBuf {
    PathBuf::from(RESULTS_DIR).join("benchmarks.csv")
}

/// Registered systems. `PlaceholderSystem` is deliberately absent so test rows
/// never reach a real dataset.
pub fn systems() -> Vec<Box<dyn System>> {
    vec![
        Box::new(Groth16System::new()),
        Box::new(PlonkSystem::new()),
        Box::new(BulletproofsSystem::new()),
        Box::new(StarkSystem::new()),
        Box::new(Halo2System::new()),
        Box::new(SpartanSystem::new()),
    ]
}

pub fn run(config: &RunConfig) -> Result<SweepResult, Error> {
    run_systems(systems(), config)
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else {
        format!("{:.0}m{:.0}s", (seconds / 60.0).floor(), seconds % 60.0)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SweepSummary {
    pub records: usize,
    pub failures: Vec<Failure>,
}

/// A sweep can run for hours, so failures must be visible while it runs.
fn push_failure(result: &mut SweepSummary, failure: Failure) {
    println!("    FAILED: {}", failure.message);
    result.failures.push(failure);
}

fn write_record<W: Write>(writer: &mut W, record: &Record) -> Result<(), Error> {
    match record.proof_size_bytes {
        Some(size) => writeln!(
            writer,
            "{},{},{},{},{},{},{}",
            record.system,
            record.field,
            record.rounds,
            record.phase,
            record.sample,
            record.time.as_nanos(),
            size,
        )?,
        None => writeln!(
            writer,
            "{},{},{},{},{},{},",
            record.system,
            record.field,
            record.rounds,
            record.phase,
            record.sample,
            record.time.as_nanos(),
        )?,
    }
    Ok(())
}

type Selection = (Vec<Box<dyn System>>, Vec<usize>);

fn select_systems(
    mut registry: Vec<Box<dyn System>>,
    config: &RunConfig,
) -> Result<Selection, Error> {
    if config.samples == 0 {
        return Err(Error::InvalidConfig(
            "sample count must be at least 1".to_string(),
        ));
    }
    if config.setup_samples == 0 {
        return Err(Error::InvalidConfig(
            "setup sample count must be at least 1".to_string(),
        ));
    }

    for name in &config.systems {
        if !registry.iter().any(|system| system.name() == name.as_str()) {
            return Err(Error::UnknownSystem(name.clone()));
        }
    }
    if !config.systems.is_empty() {
        registry.retain(|system| {
            config
                .systems
                .iter()
                .any(|name| name.as_str() == system.name())
        });
    }
    if registry.is_empty() {
        return Err(Error::NoSystems);
    }

    let rounds = if config.rounds.is_empty() {
        sweep_rounds()
    } else {
        config.rounds.clone()
    };
    for &rounds in &rounds {
        if rounds == 0 || !rounds.is_power_of_two() || rounds > mimc::MAX_ROUNDS {
            return Err(Error::InvalidConfig(format!(
                "round count must be a power of two in 1..={}, got {rounds}",
                mimc::MAX_ROUNDS
            )));
        }
    }

    Ok((registry, rounds))
}

pub fn run_systems(
    registry: Vec<Box<dyn System>>,
    config: &RunConfig,
) -> Result<SweepResult, Error> {
    let (registry, rounds) = select_systems(registry, config)?;
    let mut records = Vec::new();
    let summary = run_selected(registry, rounds, config, &mut |record| {
        records.push(record);
        Ok(())
    })?;
    Ok(SweepResult {
        records,
        failures: summary.failures,
    })
}

pub fn run_to_csv(config: &RunConfig) -> Result<SweepSummary, Error> {
    run_to_csv_systems(systems(), config)
}

/// Write the header first and flush every row, so an interrupted sweep keeps
/// every completed row.
pub fn run_to_csv_systems(
    registry: Vec<Box<dyn System>>,
    config: &RunConfig,
) -> Result<SweepSummary, Error> {
    let (registry, rounds) = select_systems(registry, config)?;
    let path = &config.output;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let file = fs::File::create(path)?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{CSV_HEADER}")?;
    writer.flush()?;

    run_selected(registry, rounds, config, &mut |record| {
        write_record(&mut writer, &record)?;
        writer.flush()?;
        Ok(())
    })
}

fn run_selected(
    registry: Vec<Box<dyn System>>,
    rounds: Vec<usize>,
    config: &RunConfig,
    sink: &mut dyn FnMut(Record) -> Result<(), Error>,
) -> Result<SweepSummary, Error> {
    let max_rounds = *rounds.iter().max().expect("round list is never empty");

    let total_systems = registry.len();
    let sweep_start = Instant::now();
    println!(
        "sweep: {total_systems} systems x {} round counts, {} setup samples, {} prove/verify samples, warm-up pairs per configuration: {}",
        rounds.len(),
        config.setup_samples,
        config.samples,
        config.warmup
    );
    println!(
        "rounds: {}",
        rounds
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    );

    let mut result = SweepSummary::default();
    let mut records = 0usize;
    for (system_index, mut system) in registry.into_iter().enumerate() {
        let name = system.name().to_string();
        let field = system.field().to_string();
        println!();
        println!("[{}/{}] {name} ({field})", system_index + 1, total_systems);

        // Universal parameters are built once, outside every timer.
        let universal_start = Instant::now();
        let universal = system.prepare_universal(max_rounds);
        let universal_time = universal_start.elapsed();
        if let Err(error) = universal {
            push_failure(
                &mut result,
                Failure {
                    system: name.clone(),
                    rounds: max_rounds,
                    message: error.to_string(),
                },
            );
            continue;
        }
        println!(
            "  universal parameters up to r={max_rounds}: {}",
            format_duration(universal_time)
        );

        for &rounds in &rounds {
            println!("  r={rounds}");
            if let Err(error) = system.prepare(rounds) {
                push_failure(
                    &mut result,
                    Failure {
                        system: name.clone(),
                        rounds,
                        message: error.to_string(),
                    },
                );
                continue;
            }

            // All three phases are timed here, at the same call boundary.
            if system.has_setup() {
                let setup_start = Instant::now();
                let mut setup_ok = true;
                for sample in 0..config.setup_samples {
                    let start = Instant::now();
                    let outcome = system.setup();
                    let time = start.elapsed();

                    match outcome {
                        Ok(()) => {
                            if time >= Duration::from_secs(1) {
                                println!(
                                    "      setup sample {}/{}: {}",
                                    sample + 1,
                                    config.setup_samples,
                                    format_duration(time)
                                );
                            }
                            sink(Record {
                                system: name.clone(),
                                field: field.clone(),
                                rounds,
                                phase: Phase::Setup,
                                sample,
                                time,
                                proof_size_bytes: None,
                            })?;
                            records += 1;
                        }
                        Err(error) => {
                            push_failure(
                                &mut result,
                                Failure {
                                    system: name.clone(),
                                    rounds,
                                    message: error.to_string(),
                                },
                            );
                            setup_ok = false;
                            break;
                        }
                    }
                }
                if !setup_ok {
                    continue;
                }
                println!(
                    "    setup {} samples: {}",
                    config.setup_samples,
                    format_duration(setup_start.elapsed())
                );
            } else {
                println!("    setup: none");
            }

            let warmup_start = Instant::now();
            if config.warmup > 0 {
                if let Err(error) = system.prepare_instance(rounds, config.samples) {
                    push_failure(
                        &mut result,
                        Failure {
                            system: name.clone(),
                            rounds,
                            message: error.to_string(),
                        },
                    );
                    continue;
                }
            }

            let mut warmup_failed = false;
            for _ in 0..config.warmup {
                let proof = match system.prove() {
                    Ok(proof) => proof,
                    Err(error) => {
                        push_failure(
                            &mut result,
                            Failure {
                                system: name.clone(),
                                rounds,
                                message: error.to_string(),
                            },
                        );
                        warmup_failed = true;
                        break;
                    }
                };

                match system.verify(&proof) {
                    Ok(true) => {}
                    Ok(false) => {
                        push_failure(
                            &mut result,
                            Failure {
                                system: name.clone(),
                                rounds,
                                message: "proof did not verify".to_string(),
                            },
                        );
                        warmup_failed = true;
                        break;
                    }
                    Err(error) => {
                        push_failure(
                            &mut result,
                            Failure {
                                system: name.clone(),
                                rounds,
                                message: error.to_string(),
                            },
                        );
                        warmup_failed = true;
                        break;
                    }
                }
            }
            if warmup_failed {
                continue;
            }
            if config.warmup > 0 {
                println!(
                    "    warm-up: {} prove/verify pairs in {}",
                    config.warmup,
                    format_duration(warmup_start.elapsed())
                );
            }

            let mut prove_total = Duration::ZERO;
            let mut verify_total = Duration::ZERO;
            let mut proof_size = 0;
            let mut proved = 0;
            for sample in 0..config.samples {
                if let Err(error) = system.prepare_instance(rounds, sample) {
                    push_failure(
                        &mut result,
                        Failure {
                            system: name.clone(),
                            rounds,
                            message: error.to_string(),
                        },
                    );
                    break;
                }

                let start = Instant::now();
                let proof = match system.prove() {
                    Ok(proof) => proof,
                    Err(error) => {
                        push_failure(
                            &mut result,
                            Failure {
                                system: name.clone(),
                                rounds,
                                message: error.to_string(),
                            },
                        );
                        break;
                    }
                };
                let prove_time = start.elapsed();

                // Serialisation and size measurement are outside both timers.
                let size = match system.proof_size(&proof) {
                    Ok(size) => size,
                    Err(error) => {
                        push_failure(
                            &mut result,
                            Failure {
                                system: name.clone(),
                                rounds,
                                message: error.to_string(),
                            },
                        );
                        break;
                    }
                };
                proof_size = size;

                let start = Instant::now();
                let valid = match system.verify(&proof) {
                    Ok(valid) => valid,
                    Err(error) => {
                        push_failure(
                            &mut result,
                            Failure {
                                system: name.clone(),
                                rounds,
                                message: error.to_string(),
                            },
                        );
                        break;
                    }
                };
                let verify_time = start.elapsed();

                if !valid {
                    push_failure(
                        &mut result,
                        Failure {
                            system: name.clone(),
                            rounds,
                            message: "proof did not verify".to_string(),
                        },
                    );
                    break;
                }

                if prove_time + verify_time >= Duration::from_secs(1) {
                    println!(
                        "      sample {}/{}: prove {}, verify {}",
                        sample + 1,
                        config.samples,
                        format_duration(prove_time),
                        format_duration(verify_time)
                    );
                }
                prove_total += prove_time;
                verify_total += verify_time;
                proved += 1;

                sink(Record {
                    system: name.clone(),
                    field: field.clone(),
                    rounds,
                    phase: Phase::Prove,
                    sample,
                    time: prove_time,
                    proof_size_bytes: Some(size),
                })?;
                sink(Record {
                    system: name.clone(),
                    field: field.clone(),
                    rounds,
                    phase: Phase::Verify,
                    sample,
                    time: verify_time,
                    proof_size_bytes: None,
                })?;
                records += 2;
            }
            println!(
                "    prove {proved}/{}: {}, verify: {}, proof {proof_size} B",
                config.samples,
                format_duration(prove_total),
                format_duration(verify_total)
            );
        }
    }

    result.records = records;
    println!();
    println!(
        "sweep finished: {} records, {} failures, {}",
        result.records,
        result.failures.len(),
        format_duration(sweep_start.elapsed())
    );

    Ok(result)
}

pub fn write_csv<W: Write>(mut writer: W, result: &SweepResult) -> Result<(), Error> {
    writeln!(writer, "{CSV_HEADER}")?;
    for record in &result.records {
        write_record(&mut writer, record)?;
    }
    Ok(())
}

pub fn write_csv_file(path: &Path, result: &SweepResult) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let file = fs::File::create(path)?;
    write_csv(BufWriter::new(file), result)
}

pub fn metadata_path(csv_path: &Path) -> PathBuf {
    let mut path = csv_path.to_path_buf();
    path.set_extension("meta.json");
    path
}

pub fn write_run_metadata(path: &Path, config: &RunConfig) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let rounds = if config.rounds.is_empty() {
        sweep_rounds()
    } else {
        config.rounds.clone()
    };
    // An empty selector means every registered system, so resolve the names.
    let system_names = if config.systems.is_empty() {
        systems()
            .iter()
            .map(|system| system.name().to_string())
            .collect::<Vec<_>>()
    } else {
        config.systems.clone()
    };
    let generated = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let metadata = serde_json::json!({
        "generated_unix_seconds": generated,
        "git_commit": git_commit(),
        "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": std::env::var("HOSTNAME").ok(),
        "cpu_model": cpu_model(),
        "systems": &system_names,
        "rounds": &rounds,
        "samples": config.samples,
        "setup_samples": config.setup_samples,
        "warmup": config.warmup,
        "preimage_seed_domain": std::str::from_utf8(BENCHMARK_SEED_DOMAIN)
            .unwrap_or("non-utf8"),
        "preimage_rule": "uniform_from_seed(blake3(domain || rounds_le || sample_le))",
        "csv_file": config.output.file_name().and_then(|name| name.to_str()),
    });

    fs::write(path, serde_json::to_vec_pretty(&metadata)?)?;
    Ok(())
}

fn git_commit() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(text.trim().to_string())
}

fn cpu_model() -> Option<String> {
    let text = fs::read_to_string("/proc/cpuinfo").ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix("model name")
            .and_then(|rest| rest.split_once(':'))
            .map(|(_, value)| value.trim().to_string())
    })
}
