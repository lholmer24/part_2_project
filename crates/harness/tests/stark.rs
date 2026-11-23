//! STARK harness acceptance test.

use harness::{run_systems, Phase, StarkSystem};

#[test]
fn stark_round_trip_through_harness() {
    let config = harness::RunConfig {
        rounds: vec![1, 4],
        setup_samples: 1,
        samples: 1,
        warmup: 0,
        ..harness::RunConfig::default()
    };

    let result = run_systems(vec![Box::new(StarkSystem::new())], &config).expect("run stark");

    assert!(result.failures.is_empty(), "{:?}", result.failures);

    // Transparent: one prove and one verify row per round count.
    assert_eq!(result.records.len(), 2 * 2);

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
