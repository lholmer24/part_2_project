//! Generic benchmark harness for the MiMC preimage statement.
//!
//! Setup, proving and verification are measured as separate phases. The CSV
//! records one row per timed phase repetition:
//!
//! ```text
//! system,field,rounds,phase,sample,time_ns,proof_size_bytes
//! ```
//!
//! [`System::prepare_universal`] runs once per system before the round sweep.
//! [`System::prepare`] runs once per configuration. Both are untimed. Use them
//! for file loading, reference hashing and reusable parameters.
//!
//! [`System::setup`], [`System::prove`] and [`System::verify`] are timed by
//! [`run_systems`], so every system is measured at the same call boundary.
//! Adapters must not contain timers. Circuit synthesis and witness
//! construction are measured inside the prover or setup calls.
//!
//! A system with no setup phase produces no `setup` rows. Proof size is
//! recorded on `prove` rows only.

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

/// An opaque proof returned by an adapter.
///
/// The harness never inspects the proof. The adapter downcasts it in
/// [`System::proof_size`] and [`System::verify`].
pub struct ProofBox(Box<dyn Any>);

impl ProofBox {
    /// Wrap a concrete proof value.
    pub fn new<T: Any>(proof: T) -> Self {
        Self(Box::new(proof))
    }

    /// Borrow the proof as its concrete type.
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
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
///
/// The harness owns every timer. Implementations must not measure time.
pub trait System {
    /// Short system name used in the CSV.
    fn name(&self) -> &str;

    /// Native scalar field used by this system.
    fn field(&self) -> &str;

    /// Build one-time universal parameters before the sweep.
    ///
    /// The harness calls this once per system, before any timer starts.
    /// `max_rounds` is the largest round count in the sweep. Store the
    /// parameters in a field that [`System::prepare`] does not reset.
    fn prepare_universal(&mut self, _max_rounds: usize) -> Result<(), BoxError> {
        Ok(())
    }

    /// Prepare untimed inputs for one configuration.
    ///
    /// Load constants and compute the reference hash here. Circuit synthesis,
    /// witness construction and library calls belong in the timed phases.
    fn prepare(&mut self, _rounds: usize) -> Result<(), BoxError> {
        Ok(())
    }

    /// Whether this system has a per-configuration setup phase.
    ///
    /// Return `false` for transparent systems that need no reusable
    /// preprocessing. The harness then emits no setup rows and never calls
    /// [`System::setup`].
    fn has_setup(&self) -> bool {
        true
    }

    /// Run the per-configuration setup.
    ///
    /// The harness times this call. Store the prepared state in the adapter.
    fn setup(&mut self) -> Result<(), BoxError>;

    /// Run the prover.
    ///
    /// The harness times this call. Return the proof as an opaque value.
    fn prove(&self) -> Result<ProofBox, BoxError>;

    /// Serialise the proof and return its size in bytes.
    ///
    /// The harness calls this after the prove timer stops.
    fn proof_size(&self, proof: &ProofBox) -> Result<usize, BoxError>;

    /// Run the verifier.
    ///
    /// The harness times this call.
    fn verify(&self, proof: &ProofBox) -> Result<bool, BoxError>;
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

/// The full round-count sweep, `r = 2^k` up to [`mimc::MAX_ROUNDS`].
pub fn sweep_rounds() -> Vec<usize> {
    (0..=mimc::MAX_ROUNDS.trailing_zeros())
        .map(|k| 1usize << k)
        .collect()
}

/// Default CSV path, under `results/`.
pub fn default_output_path() -> PathBuf {
    PathBuf::from(RESULTS_DIR).join("benchmarks.csv")
}

/// All registered systems.
///
/// Add each proof system here once its adapter implements [`System`].
/// [`PlaceholderSystem`] is intentionally not registered. Tests pass it to
/// [`run_systems`] directly so its rows never reach a real dataset.
pub fn systems() -> Vec<Box<dyn System>> {
    vec![Box::new(Groth16System::new())]
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

    let max_rounds = *rounds.iter().max().expect("round list is never empty");

    let mut result = SweepResult::default();
    for system in &mut registry {
        let name = system.name().to_string();
        let field = system.field().to_string();

        // Universal parameters are built once, outside every timer.
        if let Err(error) = system.prepare_universal(max_rounds) {
            result.failures.push(Failure {
                system: name.clone(),
                rounds: max_rounds,
                message: error.to_string(),
            });
            continue;
        }

        for &rounds in &rounds {
            if let Err(error) = system.prepare(rounds) {
                result.failures.push(Failure {
                    system: name.clone(),
                    rounds,
                    message: error.to_string(),
                });
                continue;
            }

            // All three phases are timed here, at the same call boundary.
            if system.has_setup() {
                let mut setup_ok = true;
                for sample in 0..config.setup_samples {
                    let start = Instant::now();
                    let outcome = system.setup();
                    let time = start.elapsed();

                    match outcome {
                        Ok(()) => result.records.push(Record {
                            system: name.clone(),
                            field: field.clone(),
                            rounds,
                            phase: Phase::Setup,
                            sample,
                            time,
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
                let proof = match system.prove() {
                    Ok(proof) => proof,
                    Err(error) => {
                        result.failures.push(Failure {
                            system: name.clone(),
                            rounds,
                            message: error.to_string(),
                        });
                        failed = true;
                        break;
                    }
                };

                match system.verify(&proof) {
                    Ok(true) => {}
                    Ok(false) => {
                        result.failures.push(Failure {
                            system: name.clone(),
                            rounds,
                            message: "proof did not verify".to_string(),
                        });
                        failed = true;
                        break;
                    }
                    Err(error) => {
                        result.failures.push(Failure {
                            system: name.clone(),
                            rounds,
                            message: error.to_string(),
                        });
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                continue;
            }

            for sample in 0..config.samples {
                let start = Instant::now();
                let proof = match system.prove() {
                    Ok(proof) => proof,
                    Err(error) => {
                        result.failures.push(Failure {
                            system: name.clone(),
                            rounds,
                            message: error.to_string(),
                        });
                        break;
                    }
                };
                let prove_time = start.elapsed();

                // Serialisation and size measurement are outside both timers.
                let proof_size = match system.proof_size(&proof) {
                    Ok(size) => size,
                    Err(error) => {
                        result.failures.push(Failure {
                            system: name.clone(),
                            rounds,
                            message: error.to_string(),
                        });
                        break;
                    }
                };

                let start = Instant::now();
                let valid = match system.verify(&proof) {
                    Ok(valid) => valid,
                    Err(error) => {
                        result.failures.push(Failure {
                            system: name.clone(),
                            rounds,
                            message: error.to_string(),
                        });
                        break;
                    }
                };
                let verify_time = start.elapsed();

                if !valid {
                    result.failures.push(Failure {
                        system: name.clone(),
                        rounds,
                        message: "proof did not verify".to_string(),
                    });
                    break;
                }

                result.records.push(Record {
                    system: name.clone(),
                    field: field.clone(),
                    rounds,
                    phase: Phase::Prove,
                    sample,
                    time: prove_time,
                    proof_size_bytes: Some(proof_size),
                });
                result.records.push(Record {
                    system: name.clone(),
                    field: field.clone(),
                    rounds,
                    phase: Phase::Verify,
                    sample,
                    time: verify_time,
                    proof_size_bytes: None,
                });
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
