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

    // Halo2 has key generation, so each round count writes one setup row, one
    // prove row and one verify row.
    assert_eq!(result.records.len(), 2 * 3);

    for record in result
        .records
        .iter()
        .filter(|record| record.phase == Phase::Prove)
    {
        assert!(
            record.proof_size_bytes.is_some_and(|size| size > 0),
            "proof size missing"
        );
    }
}
