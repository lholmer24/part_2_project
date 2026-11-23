//! Harness tests.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harness::{
    default_output_path, run, run_systems, sweep_rounds, write_csv, BoxError, Error, Phase,
    PlaceholderSystem, ProofBox, Record, RunConfig, SweepResult, System, CSV_HEADER,
    DEFAULT_SAMPLES, DEFAULT_SETUP_SAMPLES,
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

    let result =
        run_systems(vec![Box::new(PlaceholderSystem::new())], &config).expect("run placeholder");
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

    let result =
        run_systems(vec![Box::new(PlaceholderSystem::new())], &config).expect("run placeholder");
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

    assert!(matches!(
        run_systems(vec![Box::new(PlaceholderSystem::new())], &config),
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn run_rejects_zero_setup_samples() {
    let config = RunConfig {
        systems: vec!["placeholder".to_string()],
        rounds: vec![1],
        setup_samples: 0,
        ..RunConfig::default()
    };

    assert!(matches!(
        run_systems(vec![Box::new(PlaceholderSystem::new())], &config),
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn run_rejects_bad_round_count() {
    let config = RunConfig {
        systems: vec!["placeholder".to_string()],
        rounds: vec![3],
        ..RunConfig::default()
    };

    assert!(matches!(
        run_systems(vec![Box::new(PlaceholderSystem::new())], &config),
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn writes_csv_file_and_creates_parent() {
    let dir = std::env::temp_dir().join("harness-csv-test");
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("nested").join("run.csv");
    let result = sweep_result();

    harness::write_csv_file(&path, &result).expect("write CSV file");
    let text = std::fs::read_to_string(&path).expect("read CSV file");
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(text.lines().next(), Some(CSV_HEADER));
}

#[test]
fn writes_metadata_sidecar() {
    let dir = std::env::temp_dir().join("harness-metadata-test");
    let _ = std::fs::remove_dir_all(&dir);
    let csv = dir.join("run.csv");
    let metadata = harness::metadata_path(&csv);

    assert_eq!(metadata, dir.join("run.meta.json"));

    let config = RunConfig {
        rounds: vec![1, 2],
        samples: 3,
        setup_samples: 4,
        ..RunConfig::default()
    };
    harness::write_run_metadata(&metadata, &config).expect("write metadata");

    let text = std::fs::read_to_string(&metadata).expect("read metadata");
    assert!(text.contains("\"samples\": 3"));
    assert!(text.contains("\"rounds\": ["));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn registry_contains_groth16() {
    let names: Vec<String> = harness::systems()
        .iter()
        .map(|system| system.name().to_string())
        .collect();

    assert!(names.iter().any(|name| name == "groth16"));
}

#[test]
fn registry_contains_bulletproofs() {
    let names: Vec<String> = harness::systems()
        .iter()
        .map(|system| system.name().to_string())
        .collect();

    assert!(names.iter().any(|name| name == "bulletproofs"));
}

#[test]
fn registry_contains_stark() {
    let names: Vec<String> = harness::systems()
        .iter()
        .map(|system| system.name().to_string())
        .collect();

    assert!(names.iter().any(|name| name == "stark"));
}

#[test]
fn registry_contains_halo2() {
    let names: Vec<String> = harness::systems()
        .iter()
        .map(|system| system.name().to_string())
        .collect();

    assert!(names.iter().any(|name| name == "halo2"));
}

#[test]
fn registry_contains_spartan() {
    let names: Vec<String> = harness::systems()
        .iter()
        .map(|system| system.name().to_string())
        .collect();

    assert!(names.iter().any(|name| name == "spartan"));
}

#[test]
fn placeholder_is_not_registered() {
    let names: Vec<String> = harness::systems()
        .iter()
        .map(|system| system.name().to_string())
        .collect();

    assert!(!names.iter().any(|name| name == "placeholder"));
}

#[test]
fn registered_field_names_are_known() {
    let known = [
        mimc::field_names::BLS12_381_FR,
        mimc::field_names::RISTRETTO255_SCALAR,
        mimc::field_names::PASTA_FP,
        mimc::field_names::WINTERFELL_F128,
    ];

    for system in harness::systems() {
        assert!(
            known.contains(&system.field()),
            "{} has unknown field {}",
            system.name(),
            system.field()
        );
    }
}

#[test]
fn groth16_field_matches_its_field_type() {
    use mimc::MimcField;

    assert_eq!(
        harness::Groth16System::new().field(),
        <ark_bls12_381::Fr as MimcField>::NAME
    );
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

    fn setup(&mut self) -> Result<(), BoxError> {
        panic!("setup must not be called for a system without setup");
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        Ok(ProofBox::new(0u8))
    }

    fn proof_size(&self, _proof: &ProofBox) -> Result<usize, BoxError> {
        Ok(0)
    }

    fn verify(&self, _proof: &ProofBox) -> Result<bool, BoxError> {
        Ok(true)
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

#[derive(Clone, Default)]
struct InstanceRecorder {
    instances: Arc<Mutex<Vec<usize>>>,
}

impl System for InstanceRecorder {
    fn name(&self) -> &str {
        "instance-recorder"
    }

    fn field(&self) -> &str {
        "none"
    }

    fn has_setup(&self) -> bool {
        false
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        unreachable!("instance recorder has no setup")
    }

    fn prepare_instance(&mut self, _rounds: usize, instance: usize) -> Result<(), BoxError> {
        self.instances.lock().unwrap().push(instance);
        Ok(())
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        Ok(ProofBox::new(0u8))
    }

    fn proof_size(&self, _proof: &ProofBox) -> Result<usize, BoxError> {
        Ok(0)
    }

    fn verify(&self, _proof: &ProofBox) -> Result<bool, BoxError> {
        Ok(true)
    }
}

#[test]
fn prepare_instance_runs_for_warmup_and_each_sample() {
    let recorder = InstanceRecorder::default();
    let instances = recorder.instances.clone();
    let config = RunConfig {
        rounds: vec![1],
        samples: 3,
        warmup: 1,
        ..RunConfig::default()
    };

    run_systems(vec![Box::new(recorder)], &config).expect("run instance recorder");

    assert_eq!(*instances.lock().unwrap(), vec![3, 0, 1, 2]);
}

#[derive(Clone, Default)]
struct UniversalCounter {
    calls: Arc<AtomicUsize>,
}

impl System for UniversalCounter {
    fn name(&self) -> &str {
        "universal-counter"
    }

    fn field(&self) -> &str {
        "none"
    }

    fn prepare_universal(&mut self, _max_rounds: usize) -> Result<(), BoxError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        Ok(())
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        Ok(ProofBox::new(0u8))
    }

    fn proof_size(&self, _proof: &ProofBox) -> Result<usize, BoxError> {
        Ok(0)
    }

    fn verify(&self, _proof: &ProofBox) -> Result<bool, BoxError> {
        Ok(true)
    }
}

#[test]
fn universal_preparation_runs_once_per_system() {
    let calls = Arc::new(AtomicUsize::new(0));
    let system = UniversalCounter {
        calls: calls.clone(),
    };
    let config = RunConfig {
        rounds: vec![1, 2, 4],
        setup_samples: 1,
        samples: 1,
        warmup: 0,
        ..RunConfig::default()
    };

    let result = run_systems(vec![Box::new(system)], &config).expect("run universal counter");

    assert!(result.failures.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[derive(Default)]
struct SlowSystem;

impl System for SlowSystem {
    fn name(&self) -> &str {
        "slow"
    }

    fn field(&self) -> &str {
        "none"
    }

    fn setup(&mut self) -> Result<(), BoxError> {
        std::thread::sleep(Duration::from_millis(2));
        Ok(())
    }

    fn prove(&self) -> Result<ProofBox, BoxError> {
        std::thread::sleep(Duration::from_millis(2));
        Ok(ProofBox::new(0u8))
    }

    fn proof_size(&self, _proof: &ProofBox) -> Result<usize, BoxError> {
        Ok(0)
    }

    fn verify(&self, _proof: &ProofBox) -> Result<bool, BoxError> {
        std::thread::sleep(Duration::from_millis(2));
        Ok(true)
    }
}

#[test]
fn every_phase_is_timed() {
    let config = RunConfig {
        rounds: vec![1],
        setup_samples: 1,
        samples: 1,
        warmup: 0,
        ..RunConfig::default()
    };

    let result = run_systems(vec![Box::new(SlowSystem)], &config).expect("run slow system");

    assert_eq!(result.records.len(), 3);
    for record in &result.records {
        assert!(
            record.time >= Duration::from_millis(2),
            "{} took {:?}",
            record.phase,
            record.time
        );
    }
}

#[test]
fn streaming_csv_has_header_and_one_row_per_sample() {
    let dir = std::env::temp_dir().join("harness-stream-csv-test");
    let _ = std::fs::remove_dir_all(&dir);
    let config = RunConfig {
        systems: vec!["placeholder".to_string()],
        rounds: vec![1, 2],
        setup_samples: 2,
        samples: 3,
        warmup: 1,
        output: dir.join("run.csv"),
    };

    let summary = harness::run_to_csv_systems(vec![Box::new(PlaceholderSystem::new())], &config)
        .expect("stream to CSV");
    let text = std::fs::read_to_string(&config.output).expect("read CSV");
    let _ = std::fs::remove_dir_all(&dir);

    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.first().copied(), Some(CSV_HEADER));
    assert_eq!(summary.records, 2 * (2 + 3 + 3));
    assert_eq!(lines.len(), 1 + summary.records);
    assert!(summary.failures.is_empty());
    for line in &lines[1..] {
        assert_eq!(line.matches(',').count(), 6, "row {line}");
    }
}

#[test]
fn metadata_records_every_registered_system_when_unfiltered() {
    let dir = std::env::temp_dir().join("harness-metadata-systems-test");
    let _ = std::fs::remove_dir_all(&dir);
    let csv = dir.join("run.csv");
    let metadata = harness::metadata_path(&csv);

    let config = RunConfig {
        rounds: vec![1],
        ..RunConfig::default()
    };
    harness::write_run_metadata(&metadata, &config).expect("write metadata");

    let text = std::fs::read_to_string(&metadata).expect("read metadata");
    let _ = std::fs::remove_dir_all(&dir);

    for name in [
        "groth16",
        "plonk",
        "bulletproofs",
        "stark",
        "halo2",
        "spartan",
    ] {
        assert!(text.contains(name), "metadata is missing {name}: {text}");
    }
}
