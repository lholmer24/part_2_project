//! Generic benchmark harness for the MiMC preimage statement.
//!
//! Setup, proving and verification are measured as separate phases. The CSV
//! records one row per timed phase repetition:
//!
//! ```text
//! system,field,rounds,phase,sample,time_ns,proof_size_bytes
//! ```
//!
//! A system with no setup phase produces no `setup` rows. Proof size is
//! recorded on `prove` rows only. Universal parameters that are reused across
//! configurations are built outside the sweep; this harness measures only
//! per-configuration work.

pub mod placeholder;
pub mod systems;

use std::error::Error as StdError;
use std::fmt;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use placeholder::PlaceholderSystem;
pub use systems::Groth16System;

/// Boxed error returned by a system adapter.
pub type BoxError = Box<dyn StdError + Send + Sync>;

/// Setup timings per configuration when the caller does not choose.
pub const DEFAULT_SETUP_SAMPLES: usize = 10;

/// Proof timings per configuration when the caller does not choose.
pub const DEFAULT_SAMPLES: usize = 10;

/// Warm-up prove/verify pairs per configuration when the caller does not choose.
pub const DEFAULT_WARMUP: usize = 1;

/// Directory that holds benchmark CSV files.
pub const RESULTS_DIR: &str = "results";

/// CSV header. Times are nanoseconds and sizes are bytes.
pub const CSV_HEADER: &str = "system,field,rounds,phase,sample,time_ns,proof_size_bytes";

/// One measured phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Parameter or key generation.
    Setup,
    /// Proof generation.
    Prove,
    /// Proof verification.
    Verify,
}

impl Phase {
    /// Lowercase name used in the CSV.
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

/// One timed phase repetition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Proof system name.
    pub system: String,
    /// Native scalar field, or `none` for a placeholder.
    pub field: String,
    /// Number of MiMC rounds.
    pub rounds: usize,
    /// Measured phase.
    pub phase: Phase,
    /// Repetition index within this phase.
    pub sample: usize,
    /// Measured time.
    pub time: Duration,
    /// Serialised proof size, present on `prove` rows only.
    pub proof_size_bytes: Option<usize>,
}

/// Timings returned by [`System::measure`] for one proof and one verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofSample {
    /// Proof size in bytes.
    pub proof_size: usize,
    /// Prover time, with setup outside the timer.
    pub prove_time: Duration,
    /// Verifier time, with deserialisation outside the timer.
    pub verify_time: Duration,
}

/// One configuration that failed during a sweep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// Proof system name.
    pub system: String,
    /// Number of MiMC rounds.
    pub rounds: usize,
    /// Error message from the system adapter.
    pub message: String,
}

/// Result of a benchmark sweep.
#[derive(Clone, Debug, Default)]
pub struct SweepResult {
    /// Timed phase repetitions.
    pub records: Vec<Record>,
    /// Configurations that returned an error.
    pub failures: Vec<Failure>,
}

/// A proof system that the harness can benchmark.
pub trait System {
    /// Short system name used in the CSV.
    fn name(&self) -> &str;

    /// Native scalar field used by this system.
    fn field(&self) -> &str;

    /// Whether this system has a setup phase.
    ///
    /// Return `false` for transparent systems that need no reusable
    /// preprocessing. The harness then emits no setup rows and never calls
    /// [`System::setup`].
    fn has_setup(&self) -> bool {
        true
    }

    /// Prepare the keys or generators for `rounds`.
    ///
    /// Store the prepared state inside the adapter. The harness times this call
    /// and reuses the final state for every proof sample.
    fn setup(&mut self, rounds: usize) -> Result<(), BoxError>;

    /// Run one prove/verify pair.
    ///
    /// Time proving and verification separately. Setup must be outside both
    /// timers. Return the proof size in bytes.
    fn measure(&self, rounds: usize) -> Result<ProofSample, BoxError>;
}

/// Sweep configuration.
#[derive(Clone, Debug)]
pub struct RunConfig {
    /// Systems to run. An empty vector means every registered system.
    pub systems: Vec<String>,
    /// Round counts to run. An empty vector means [`sweep_rounds`].
    pub rounds: Vec<usize>,
    /// Timed setup runs per configuration, for systems with setup.
    pub setup_samples: usize,
    /// Timed prove/verify pairs per configuration.
    pub samples: usize,
    /// Warm-up prove/verify pairs per configuration.
    pub warmup: usize,
    /// CSV output path.
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

/// Error from the harness itself.
#[derive(Debug)]
pub enum Error {
    /// A filesystem operation failed.
    Io(io::Error),
    /// Metadata could not be encoded as JSON.
    Json(serde_json::Error),
    /// The configuration is invalid.
    InvalidConfig(String),
    /// A name in `RunConfig::systems` matches no registered system.
    UnknownSystem(String),
    /// No system matched the configuration.
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

/// The full round-count sweep, `r = 2^k` for `k = 0..15`.
pub fn sweep_rounds() -> Vec<usize> {
    (0..16).map(|k| 1usize << k).collect()
}

/// Default CSV path, under `results/`.
pub fn default_output_path() -> PathBuf {
    PathBuf::from(RESULTS_DIR).join("benchmarks.csv")
}

/// All registered systems.
///
/// Add each proof system here once its adapter implements [`System`].
pub fn systems() -> Vec<Box<dyn System>> {
    vec![
        Box::new(PlaceholderSystem::new()),
        Box::new(Groth16System::new()),
    ]
}

/// Run the configured sweep with the registered systems.
pub fn run(config: &RunConfig) -> Result<SweepResult, Error> {
    run_systems(systems(), config)
}

/// Run the configured sweep with an explicit system list.
///
/// This is the testable entry point. [`run`] calls it with [`systems`].
pub fn run_systems(
    mut registry: Vec<Box<dyn System>>,
    config: &RunConfig,
) -> Result<SweepResult, Error> {
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

    let mut result = SweepResult::default();
    for system in &mut registry {
        for &rounds in &rounds {
            let name = system.name().to_string();
            let field = system.field().to_string();

            if system.has_setup() {
                let mut setup_ok = true;
                for sample in 0..config.setup_samples {
                    let start = Instant::now();
                    match system.setup(rounds) {
                        Ok(()) => result.records.push(Record {
                            system: name.clone(),
                            field: field.clone(),
                            rounds,
                            phase: Phase::Setup,
                            sample,
                            time: start.elapsed(),
                            proof_size_bytes: None,
                        }),
                        Err(error) => {
                            result.failures.push(Failure {
                                system: name.clone(),
                                rounds,
                                message: error.to_string(),
                            });
                            setup_ok = false;
                            break;
                        }
                    }
                }
                if !setup_ok {
                    continue;
                }
            }

            let mut failed = false;
            for _ in 0..config.warmup {
                if let Err(error) = system.measure(rounds) {
                    result.failures.push(Failure {
                        system: name.clone(),
                        rounds,
                        message: error.to_string(),
                    });
                    failed = true;
                    break;
                }
            }
            if failed {
                continue;
            }

            for sample in 0..config.samples {
                match system.measure(rounds) {
                    Ok(proof) => {
                        result.records.push(Record {
                            system: name.clone(),
                            field: field.clone(),
                            rounds,
                            phase: Phase::Prove,
                            sample,
                            time: proof.prove_time,
                            proof_size_bytes: Some(proof.proof_size),
                        });
                        result.records.push(Record {
                            system: name.clone(),
                            field: field.clone(),
                            rounds,
                            phase: Phase::Verify,
                            sample,
                            time: proof.verify_time,
                            proof_size_bytes: None,
                        });
                    }
                    Err(error) => {
                        result.failures.push(Failure {
                            system: name.clone(),
                            rounds,
                            message: error.to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }

    Ok(result)
}

/// Write phase measurements as CSV.
///
/// The first line is [`CSV_HEADER`]. Each record becomes one row. Times are
/// written as integer nanoseconds. Proof size is written only on `prove` rows.
pub fn write_csv<W: Write>(mut writer: W, result: &SweepResult) -> Result<(), Error> {
    writeln!(writer, "{CSV_HEADER}")?;
    for record in &result.records {
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
    }
    Ok(())
}

/// Create `path` and write the phase measurements as CSV.
pub fn write_csv_file(path: &Path, result: &SweepResult) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let file = fs::File::create(path)?;
    write_csv(BufWriter::new(file), result)
}

/// Sidecar metadata path for a CSV path.
///
/// `results/benchmarks.csv` becomes `results/benchmarks.meta.json`.
pub fn metadata_path(csv_path: &Path) -> PathBuf {
    let mut path = csv_path.to_path_buf();
    path.set_extension("meta.json");
    path
}

/// Write run metadata next to the CSV.
///
/// The CSV holds only measurements. This sidecar records the environment and
/// sample settings that the analysis needs for reproducibility.
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
        "systems": &config.systems,
        "rounds": &rounds,
        "samples": config.samples,
        "setup_samples": config.setup_samples,
        "warmup": config.warmup,
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
