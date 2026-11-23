//! Halo2 harness acceptance test.

use harness::{run_systems, Halo2System, Phase};

#[test]
fn halo2_round_trip_through_harness() {
    let config = harness::RunConfig {
        rounds: vec![1, 4],
        setup_samples: 1,
        samples: 1,
        warmup: 0,
        ..harness::RunConfig::default()
    };

    let result = run_systems(vec![Box::new(Halo2System::new())], &config).expect("run halo2");

    assert!(result.failures.is_empty(), "{:?}", result.failures);

    // One setup, one prove and one verify row per round count.
    assert_eq!(result.records.len(), 2 * 3);

    let sizes: Vec<usize> = result
        .records
        .iter()
        .filter(|record| record.phase == Phase::Prove)
        .map(|record| record.proof_size_bytes.expect("proof size missing"))
        .collect();

    // The two round counts use different domains, so proof sizes must differ.
    assert_eq!(sizes.len(), 2);
    assert_ne!(
        sizes[0], sizes[1],
        "both configurations used the same domain"
    );
}
