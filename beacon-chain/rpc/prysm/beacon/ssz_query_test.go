package beacon

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OffchainLabs/go-bitfield"
	"github.com/OffchainLabs/prysm/v7/api"
	"github.com/OffchainLabs/prysm/v7/api/server/structs"
	chainMock "github.com/OffchainLabs/prysm/v7/beacon-chain/blockchain/testing"
	"github.com/OffchainLabs/prysm/v7/beacon-chain/rpc/testutil"
	"github.com/OffchainLabs/prysm/v7/consensus-types/blocks"
	"github.com/OffchainLabs/prysm/v7/consensus-types/interfaces"
	"github.com/OffchainLabs/prysm/v7/consensus-types/primitives"
	"github.com/OffchainLabs/prysm/v7/encoding/ssz/query"
	eth "github.com/OffchainLabs/prysm/v7/proto/prysm/v1alpha1"
	sszquerypb "github.com/OffchainLabs/prysm/v7/proto/ssz_query"
	"github.com/OffchainLabs/prysm/v7/runtime/version"
	"github.com/OffchainLabs/prysm/v7/testing/assert"
	"github.com/OffchainLabs/prysm/v7/testing/require"
	"github.com/OffchainLabs/prysm/v7/testing/util"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ssz "github.com/prysmaticlabs/fastssz"
)

func TestQueryBeaconState(t *testing.T) {
	ctx := context.Background()

	st, _ := util.DeterministicGenesisState(t, 16)
	slot := primitives.Slot(42)
	require.NoError(t, st.SetSlot(slot))
	require.NoError(t, st.UpdateBalancesAtIndex(0, 42000000000))

	stateRoot, err := st.HashTreeRoot(ctx)
	require.NoError(t, err)

	// Define expected values for various paths
	slotExpectedValue, _ := slot.MarshalSSZ()
	headerExpectedValue, _ := st.LatestBlockHeader().MarshalSSZ()
	proposerIndexExpectedValue := func() []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(st.LatestBlockHeader().ProposerIndex))
		return b
	}()
	validatorsExpectedValue := func() []byte {
		b := make([]byte, 0)
		validators := st.Validators()
		for _, v := range validators {
			vBytes, _ := v.MarshalSSZ()
			b = append(b, vBytes...)
		}
		return b
	}()

	tests := []struct {
		path          string
		expectedValue []byte
		includeProof  bool
	}{
		{
			path:          ".slot",
			expectedValue: slotExpectedValue,
		},
		{
			path:          ".slot",
			expectedValue: slotExpectedValue,
			includeProof:  true,
		},
		{
			path:          ".latest_block_header",
			expectedValue: headerExpectedValue,
		},
		{
			path:          ".latest_block_header",
			expectedValue: headerExpectedValue,
			includeProof:  true,
		},

		{
			path:          ".latest_block_header.proposer_index",
			expectedValue: proposerIndexExpectedValue,
		},

		{
			path:          ".latest_block_header.proposer_index",
			expectedValue: proposerIndexExpectedValue,
			includeProof:  true,
		},
		{
			path:          ".validators",
			expectedValue: validatorsExpectedValue,
		},
		{
			path:          ".validators",
			expectedValue: validatorsExpectedValue,
			includeProof:  true,
		},
		{
			path: ".validators[0]",
			expectedValue: func() []byte {
				v, _ := st.ValidatorAtIndex(0)
				result, _ := v.MarshalSSZ()
				return result
			}(),
		},
		{
			path: ".validators[0].withdrawal_credentials",
			expectedValue: func() []byte {
				v, _ := st.ValidatorAtIndex(0)
				return v.WithdrawalCredentials
			}(),
		},
		{
			path: ".validators[0].effective_balance",
			expectedValue: func() []byte {
				v, _ := st.ValidatorAtIndex(0)
				b := make([]byte, 8)
				binary.LittleEndian.PutUint64(b, uint64(v.EffectiveBalance))
				return b
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("path=%s, includeProof=%t", tt.path, tt.includeProof), func(t *testing.T) {
			chainService := &chainMock.ChainService{Optimistic: false, FinalizedRoots: make(map[[32]byte]bool)}
			s := &Server{
				OptimisticModeFetcher: chainService,
				FinalizationFetcher:   chainService,
				Stater: &testutil.MockStater{
					BeaconStateRoot: stateRoot[:],
					BeaconState:     st,
				},
			}

			requestBody := &structs.SSZQueryRequest{
				Query:        tt.path,
				IncludeProof: tt.includeProof,
			}
			var buf bytes.Buffer
			require.NoError(t, json.NewEncoder(&buf).Encode(requestBody))

			request := httptest.NewRequest(http.MethodPost, "http://example.com/prysm/v1/beacon/states/{state_id}/query", &buf)
			request.SetPathValue("state_id", "head")
			writer := httptest.NewRecorder()
			writer.Body = &bytes.Buffer{}

			s.QueryBeaconState(writer, request)
			require.Equal(t, http.StatusOK, writer.Code)
			assert.Equal(t, version.String(version.Phase0), writer.Header().Get(api.VersionHeader))

			if !tt.includeProof {
				expectedResponse := &sszquerypb.SSZQueryResponse{
					Root:   stateRoot[:],
					Result: tt.expectedValue,
				}
				sszExpectedResponse, err := expectedResponse.MarshalSSZ()
				require.NoError(t, err)
				require.DeepEqual(t, sszExpectedResponse, writer.Body.Bytes())
				return
			}

			responseData := writer.Body.Bytes()
			var response sszquerypb.SSZQueryResponseWithProof
			require.NoError(t, response.UnmarshalSSZ(responseData))

			// Verify the proof is included
			require.NotNil(t, response.Proof)
			require.Equal(t, true, len(response.Proof.Proofs) > 0, "merkle proof should not be empty")

			// Verify the result
			require.DeepEqual(t, tt.expectedValue, response.Result)
			require.DeepEqual(t, stateRoot[:], response.Root)

			// Verify the merkle proof
			merkleProof := &ssz.Proof{
				Index:  int(response.Proof.Gindex),
				Leaf:   response.Proof.Leaf,
				Hashes: response.Proof.Proofs,
			}
			isValid, err := ssz.VerifyProof(response.Root, merkleProof)
			require.NoError(t, err)
			require.Equal(t, true, isValid, "merkle proof verification failed")
		})
	}
}

func TestQueryBeaconStateInvalidRequest(t *testing.T) {
	ctx := context.Background()

	st, _ := util.DeterministicGenesisState(t, 16)
	require.NoError(t, st.SetSlot(primitives.Slot(42)))
	stateRoot, err := st.HashTreeRoot(ctx)
	require.NoError(t, err)

	tests := []struct {
		name        string
		stateId     string
		path        string
		code        int
		errorString string
	}{
		{
			name:        "empty query submitted",
			stateId:     "head",
			path:        "",
			errorString: "Empty query submitted",
		},
		{
			name:        "invalid path",
			stateId:     "head",
			path:        ".invalid[]]",
			errorString: "Could not parse path",
		},
		{
			name:        "non-existent field",
			stateId:     "head",
			path:        ".non_existent_field",
			code:        http.StatusInternalServerError,
			errorString: "Could not calculate offset and length for path",
		},
		{
			name:    "empty state ID",
			stateId: "",
			path:    "",
		},
		{
			name:    "far future slot",
			stateId: "1000000000000",
			path:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			chainService := &chainMock.ChainService{Optimistic: false, FinalizedRoots: make(map[[32]byte]bool)}
			s := &Server{
				OptimisticModeFetcher: chainService,
				FinalizationFetcher:   chainService,
				Stater: &testutil.MockStater{
					BeaconStateRoot: stateRoot[:],
					BeaconState:     st,
				},
			}

			requestBody := &structs.SSZQueryRequest{
				Query: tt.path,
			}
			var buf bytes.Buffer
			require.NoError(t, json.NewEncoder(&buf).Encode(requestBody))

			request := httptest.NewRequest(http.MethodPost, "http://example.com/prysm/v1/beacon/states/{state_id}/query", &buf)
			request.SetPathValue("state_id", tt.stateId)
			writer := httptest.NewRecorder()
			writer.Body = &bytes.Buffer{}

			s.QueryBeaconState(writer, request)

			if tt.code == 0 {
				tt.code = http.StatusBadRequest
			}
			require.Equal(t, tt.code, writer.Code)
			if tt.errorString != "" {
				errorString := writer.Body.String()
				require.Equal(t, true, strings.Contains(errorString, tt.errorString))
			}
		})
	}
}

func TestQueryBeaconBlock(t *testing.T) {
	randaoReveal, err := hexutil.Decode("0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505")
	require.NoError(t, err)
	root, err := hexutil.Decode("0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2")
	require.NoError(t, err)
	signature, err := hexutil.Decode("0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505")
	require.NoError(t, err)
	att := &eth.Attestation{
		AggregationBits: bitfield.Bitlist{0x01},
		Data: &eth.AttestationData{
			Slot:            1,
			CommitteeIndex:  1,
			BeaconBlockRoot: root,
			Source: &eth.Checkpoint{
				Epoch: 1,
				Root:  root,
			},
			Target: &eth.Checkpoint{
				Epoch: 1,
				Root:  root,
			},
		},
		Signature: signature,
	}

	tests := []struct {
		name          string
		path          string
		block         interfaces.ReadOnlySignedBeaconBlock
		expectedValue []byte
	}{
		{
			name: "slot",
			path: ".slot",
			block: func() interfaces.ReadOnlySignedBeaconBlock {
				b := util.NewBeaconBlock()
				b.Block.Slot = 123
				sb, err := blocks.NewSignedBeaconBlock(b)
				require.NoError(t, err)
				return sb
			}(),
			expectedValue: func() []byte {
				b := make([]byte, 8)
				binary.LittleEndian.PutUint64(b, 123)
				return b
			}(),
		},
		{
			name: "randao_reveal",
			path: ".body.randao_reveal",
			block: func() interfaces.ReadOnlySignedBeaconBlock {
				b := util.NewBeaconBlock()
				b.Block.Body.RandaoReveal = randaoReveal
				sb, err := blocks.NewSignedBeaconBlock(b)
				require.NoError(t, err)
				return sb
			}(),
			expectedValue: randaoReveal,
		},
		{
			name: "attestations",
			path: ".body.attestations",
			block: func() interfaces.ReadOnlySignedBeaconBlock {
				b := util.NewBeaconBlock()
				b.Block.Body.Attestations = []*eth.Attestation{
					att,
				}
				sb, err := blocks.NewSignedBeaconBlock(b)
				require.NoError(t, err)
				return sb
			}(),
			expectedValue: func() []byte {
				b, err := att.MarshalSSZ()
				require.NoError(t, err)
				return b
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBlockFetcher := &testutil.MockBlocker{BlockToReturn: tt.block}
			mockChainService := &chainMock.ChainService{
				FinalizedRoots: map[[32]byte]bool{},
			}
			s := &Server{
				FinalizationFetcher: mockChainService,
				Blocker:             mockBlockFetcher,
			}
			requestBody := &structs.SSZQueryRequest{
				Query: tt.path,
			}
			var buf bytes.Buffer
			require.NoError(t, json.NewEncoder(&buf).Encode(requestBody))

			request := httptest.NewRequest(http.MethodPost, "http://example.com/prysm/v1/beacon/blocks/{block_id}/query", &buf)
			request.SetPathValue("block_id", "head")
			writer := httptest.NewRecorder()
			writer.Body = &bytes.Buffer{}

			s.QueryBeaconBlock(writer, request)
			require.Equal(t, http.StatusOK, writer.Code)
			assert.Equal(t, version.String(version.Phase0), writer.Header().Get(api.VersionHeader))

			blockRoot, err := tt.block.Block().HashTreeRoot()
			require.NoError(t, err)

			expectedResponse := &sszquerypb.SSZQueryResponse{
				Root:   blockRoot[:],
				Result: tt.expectedValue,
			}
			sszExpectedResponse, err := expectedResponse.MarshalSSZ()
			require.NoError(t, err)
			assert.DeepEqual(t, sszExpectedResponse, writer.Body.Bytes())
		})
	}
}

func TestGetBeaconStateProof(t *testing.T) {
	ctx := context.Background()

	st, _ := util.DeterministicGenesisState(t, 16)
	require.NoError(t, st.SetSlot(primitives.Slot(42)))
	require.NoError(t, st.UpdateBalancesAtIndex(0, 42000000000))

	stateRoot, err := st.HashTreeRoot(ctx)
	require.NoError(t, err)

	info, err := query.AnalyzeObject(st.ToProtoUnsafe().(query.SSZObject))
	require.NoError(t, err)

	tests := []struct {
		path        string
		expectError bool
	}{
		{
			// Basic SSZ type
			path: ".slot",
		},
		{
			// Container SSZ type
			path: ".latest_block_header",
		},
		{
			// List SSZ type
			path: ".validators",
		},
		{
			// Accessing an element in a list
			path: ".validators[0]",
		},
		// {
		// 	// Accessing an element in a list
		// 	path: ".validators[0].effective_balance",
		// },
		{
			// Accessing an element in a vector
			path: ".block_roots[0]",
		},
		{
			// Accessing a field in a container
			path: ".latest_block_header.proposer_index",
		},
		{
			path:        ".wrong_path",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			path, err := query.ParsePath(tt.path)
			require.NoError(t, err)

			proof, err := getBeaconStateProof(ctx, st, info, path)
			if tt.expectError {
				require.NotNil(t, err)
				return
			}
			require.NoError(t, err)

			isValid, err := ssz.VerifyProof(stateRoot[:], &ssz.Proof{
				Index:  int(proof.Gindex),
				Leaf:   proof.Leaf,
				Hashes: proof.Proofs,
			})
			require.NoError(t, err)
			require.Equal(t, true, isValid)
		})
	}
}
