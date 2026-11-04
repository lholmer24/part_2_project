//! Harness tests.

use std::time::Duration;

use harness::{
    default_output_path, run, run_systems, sweep_rounds, write_csv, BoxError, Error, Phase,
    ProofSample, Record, RunConfig, SweepResult, System, CSV_HEADER, DEFAULT_SAMPLES,
    DEFAULT_SETUP_SAMPLES,
};

fn record(phase: Phase, sample: usize, time_ns: u64, size: Option<usize>) -> Record {
    Record {
        system: "placeholder".to_string(),
        field: "none".to_string(),
        rounds: 1,
        phase,
        sample,
        time: Duration::from_nanos(time_ns),
        proof_size_bytes: size,
    }
}

fn sweep_result() -> SweepResult {
    SweepResult {
        records: vec![
            record(Phase::Setup, 0, 100, None),
            record(Phase::Prove, 0, 2, Some(0)),
            record(Phase::Verify, 0, 3, None),
        ],
        failures: Vec::new(),
    }
}

#[test]
fn sweep_has_every_power_of_two() {
    let expected: Vec<usize> = (0..16).map(|k| 1usize << k).collect();
    assert_eq!(sweep_rounds(), expected);
}

#[test]
fn default_output_is_under_results() {
    assert_eq!(
        default_output_path(),
        std::path::PathBuf::from("results").join("benchmarks.csv")
    );
}

#[test]
fn default_config_has_ten_setup_and_proof_samples() {
    let config = RunConfig::default();
    assert_eq!(config.samples, DEFAULT_SAMPLES);
    assert_eq!(config.setup_samples, DEFAULT_SETUP_SAMPLES);
}

#[test]
fn writes_one_row_per_phase_sample() {
    let result = sweep_result();
    let mut buffer = Vec::new();
    write_csv(&mut buffer, &result).expect("write CSV");
    let text = String::from_utf8(buffer).expect("UTF-8 CSV");
    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(lines.first().copied(), Some(CSV_HEADER));
    assert_eq!(lines.len(), 1 + result.records.len());
    assert_eq!(lines[1], "placeholder,none,1,setup,0,100,");
    assert_eq!(lines[2], "placeholder,none,1,prove,0,2,0");
    assert_eq!(lines[3], "placeholder,none,1,verify,0,3,");
}

#[test]
fn placeholder_separates_all_three_phases() {
    let config = RunConfig {
        systems: vec!["placeholder".to_string()],
        rounds: vec![1, 2, 4],
        setup_samples: 4,
        samples: 3,
        ..RunConfig::default()
    };

    let result = run(&config).expect("run placeholder");
    let count = |phase| {
        result
            .records
            .iter()
            .filter(|record| record.phase == phase)
            .count()
    };

    assert!(result.failures.is_empty());
    assert_eq!(count(Phase::Setup), 3 * 4);
    assert_eq!(count(Phase::Prove), 3 * 3);
    assert_eq!(count(Phase::Verify), 3 * 3);
}

#[test]
fn warm_up_runs_are_not_recorded() {
    let config = RunConfig {
        systems: vec!["placeholder".to_string()],
        rounds: vec![1],
        setup_samples: 1,
        samples: 3,
        warmup: 2,
        ..RunConfig::default()
    };

    let result = run(&config).expect("run placeholder");
    assert_eq!(result.records.len(), 1 + 3 + 3);
    assert!(result.failures.is_empty());
}

#[test]
fn run_rejects_unknown_system() {
    let config = RunConfig {
        systems: vec!["missing".to_string()],
        rounds: vec![1],
        ..RunConfig::default()
    };

    assert!(matches!(run(&config), Err(Error::UnknownSystem(_))));
}

#[test]
fn run_rejects_zero_samples() {
    let config = RunConfig {
        systems: vec!["placeholder".to_string()],
        rounds: vec![1],
        samples: 0,
        ..RunConfig::default()
    };

    assert!(matches!(run(&config), Err(Error::InvalidConfig(_))));
}

#[test]
fn run_rejects_zero_setup_samples() {
    let config = RunConfig {
        systems: vec!["placeholder".to_string()],
        rounds: vec![1],
        setup_samples: 0,
        ..RunConfig::default()
    };

    assert!(matches!(run(&config), Err(Error::InvalidConfig(_))));
}

#[test]
fn run_rejects_bad_round_count() {
    let config = RunConfig {
        systems: vec!["placeholder".to_string()],
        rounds: vec![3],
        ..RunConfig::default()
    };

    assert!(matches!(run(&config), Err(Error::InvalidConfig(_))));
}

#[test]
fn writes_csv_file_under_results() {
    let path = std::path::Path::new("results").join("harness-test.csv");
    let result = sweep_result();

    harness::write_csv_file(&path, &result).expect("write CSV file");
    let text = std::fs::read_to_string(&path).expect("read CSV file");
    let _ = std::fs::remove_file(&path);

    assert_eq!(text.lines().next(), Some(CSV_HEADER));
}

#[derive(Default)]
struct NoSetupSystem;

impl System for NoSetupSystem {
    fn name(&self) -> &str {
        "no-setup"
    }

    fn field(&self) -> &str {
        "none"
    }

    fn has_setup(&self) -> bool {
        false
    }

    fn setup(&mut self, _rounds: usize) -> Result<(), BoxError> {
        panic!("setup must not be called for a system without setup");
    }

    fn measure(&self, _rounds: usize) -> Result<ProofSample, BoxError> {
        Ok(ProofSample {
            proof_size: 0,
            prove_time: Duration::ZERO,
            verify_time: Duration::ZERO,
        })
    }
}

#[test]
fn system_without_setup_has_no_setup_rows() {
    let config = RunConfig {
        rounds: vec![1],
        setup_samples: 5,
        samples: 2,
        ..RunConfig::default()
    };

    let result = run_systems(vec![Box::new(NoSetupSystem) as Box<dyn System>], &config)
        .expect("run no-setup system");
    let setups = result
        .records
        .iter()
        .filter(|record| record.phase == Phase::Setup)
        .count();

    assert_eq!(setups, 0);
    assert_eq!(result.records.len(), 2 + 2);
}
