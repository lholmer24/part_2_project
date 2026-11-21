//! Spartan harness acceptance test.

use harness::{run_systems, Phase, SpartanSystem};

#[test]
fn spartan_round_trip_through_harness() {
    let config = harness::RunConfig {
        rounds: vec![1, 4],
        setup_samples: 1,
        samples: 1,
        warmup: 0,
        ..harness::RunConfig::default()
    };

    let result = run_systems(vec![Box::new(SpartanSystem::new())], &config).expect("run spartan");

    assert!(result.failures.is_empty(), "{:?}", result.failures);

    // Spartan has deterministic preprocessing, so each round count writes one
    // setup row, one prove row and one verify row.
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
