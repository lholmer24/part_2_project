//! PLONK harness acceptance test.

use harness::{run_systems, Phase, PlonkSystem};

#[test]
fn plonk_round_trip_through_harness() {
    let config = harness::RunConfig {
        rounds: vec![1, 4],
        setup_samples: 1,
        samples: 1,
        warmup: 0,
        ..harness::RunConfig::default()
    };

    let result = run_systems(vec![Box::new(PlonkSystem::new())], &config).expect("run plonk");

    assert!(result.failures.is_empty(), "{:?}", result.failures);
    assert_eq!(result.records.len(), 2 * 3);

    // The PLONK proof size is fixed by the protocol, not the circuit size.
    for record in result
        .records
        .iter()
        .filter(|record| record.phase == Phase::Prove)
    {
        assert_eq!(record.proof_size_bytes, Some(1008));
    }
}
