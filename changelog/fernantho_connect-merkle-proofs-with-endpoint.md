### Added

- Added New ProofCollector type. It collects sibling hashes and leaves needed for Merkle proof during the merkleization.
  - ProofCollector uses goroutines for vector merkleization. ProofCollector is thread-safe.
  - ProofCollector returns `fastssz.Proof` enabling the usage of `fastssz` `Verify` function.
- Integrated Merkle proofs into ssz-query API endpoints
- Added testing covering the production of Merkle proof from Phase0 beacon state and benchmarked against real Hoodi beacon state (Fulu version)