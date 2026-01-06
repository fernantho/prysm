package query_test

import (
	"reflect"
	"testing"

	"github.com/OffchainLabs/prysm/v7/beacon-chain/state"
	"github.com/OffchainLabs/prysm/v7/beacon-chain/state/state-native/types"
	"github.com/OffchainLabs/prysm/v7/consensus-types/primitives"
	"github.com/OffchainLabs/prysm/v7/encoding/ssz/query"
	ethpb "github.com/OffchainLabs/prysm/v7/proto/prysm/v1alpha1"
	"github.com/OffchainLabs/prysm/v7/testing/require"
	"github.com/OffchainLabs/prysm/v7/testing/util"
)

func setupBeaconState(t testing.TB, numValidators uint64) (state.BeaconState, *ethpb.BeaconState, *query.SszInfo) {
	st, _ := util.DeterministicGenesisState(t, numValidators)
	require.NoError(t, st.SetSlot(primitives.Slot(42)))

	pb, ok := st.ToProtoUnsafe().(*ethpb.BeaconState)
	require.Equal(t, true, ok, "expected Phase0 BeaconState")

	info, err := query.AnalyzeObject(pb)
	require.NoError(t, err)

	return st, pb, info
}

func getGIndex(t testing.TB, info *query.SszInfo, pathStr string) uint64 {
	path, err := query.ParsePath(pathStr)
	require.NoError(t, err)
	gindex, err := query.GetGeneralizedIndexFromPath(info, path)
	require.NoError(t, err)
	return gindex
}

func TestBeaconStateProof_Shallow(t *testing.T) {
	st, _, info := setupBeaconState(t, 64)
	gindex := getGIndex(t, info, ".validators")

	legacyProof, err := info.Prove(gindex)
	require.NoError(t, err)

	optProof, err := st.ProofByFieldIndex(t.Context(), types.Validators)
	require.NoError(t, err)

	require.DeepEqual(t, legacyProof.Hashes, optProof)
}

func TestBeaconStateProof_Deep(t *testing.T) {
	st, pb, info := setupBeaconState(t, 64)
	gindex := getGIndex(t, info, ".validators[0]")

	legacyProof, err := info.Prove(gindex)
	require.NoError(t, err)

	topProof, err := st.ProofByFieldIndex(t.Context(), types.Validators)
	require.NoError(t, err)

	ci, err := info.ContainerInfo()
	require.NoError(t, err)

	fields := ci.Fields()
	validators := fields["validators"].SszInfo()

	collector := query.NewProofCollector()
	collector.RegisterRequiredSiblings(1 << 41)

	value := reflect.ValueOf(pb.Validators)

	_, err = collector.Merkleize(validators, value, 1)
	require.NoError(t, err)

	bottomProof, err := collector.ToProof()
	require.NoError(t, err)

	combinedProof := append(bottomProof.Hashes, topProof...)
	require.DeepEqual(t, legacyProof.Hashes, combinedProof)
}

func BenchmarkBeaconStateProof_Comparison(b *testing.B) {
	st, pb, info := setupBeaconState(b, 64)

	gindexShallow := getGIndex(b, info, ".validators")
	gindexDeep := getGIndex(b, info, ".validators[0]")

	ci, _ := info.ContainerInfo()
	fields := ci.Fields()
	vInfo := fields["validators"].SszInfo()
	vVal := reflect.ValueOf(pb.Validators)

	b.Run("Shallow (\".validators\")_Legacy", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = info.Prove(gindexShallow)
		}
	})

	b.Run("Shallow (\".validators\")_Optimized", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = st.ProofByFieldIndex(b.Context(), types.Validators)
		}
	})

	b.Run("Deep (\".validators[0]\")_Legacy", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = info.Prove(gindexDeep)
		}
	})

	b.Run("Deep (\".validators[0]\")_Optimized", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			top, _ := st.ProofByFieldIndex(b.Context(), types.Validators)

			collector := query.NewProofCollector()
			collector.RegisterRequiredSiblings(1 << 41)
			_, _ = collector.Merkleize(vInfo, vVal, 1)
			bottom, _ := collector.ToProof()

			_ = append(bottom.Hashes, top...)
		}
	})
}
