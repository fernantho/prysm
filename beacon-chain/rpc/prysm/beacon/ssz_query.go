package beacon

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/OffchainLabs/prysm/v7/api"
	"github.com/OffchainLabs/prysm/v7/api/server/structs"
	"github.com/OffchainLabs/prysm/v7/beacon-chain/rpc/eth/shared"
	"github.com/OffchainLabs/prysm/v7/beacon-chain/rpc/lookup"
	"github.com/OffchainLabs/prysm/v7/beacon-chain/state"
	"github.com/OffchainLabs/prysm/v7/beacon-chain/state/state-native/types"
	"github.com/OffchainLabs/prysm/v7/encoding/ssz/query"
	"github.com/OffchainLabs/prysm/v7/monitoring/tracing/trace"
	"github.com/OffchainLabs/prysm/v7/network/httputil"
	sszquerypb "github.com/OffchainLabs/prysm/v7/proto/ssz_query"
	"github.com/OffchainLabs/prysm/v7/runtime/version"
	ssz "github.com/prysmaticlabs/fastssz"
)

// QueryBeaconState handles SSZ Query request for BeaconState.
// Returns as bytes serialized SSZQueryResponse.
func (s *Server) QueryBeaconState(w http.ResponseWriter, r *http.Request) {
	ctx, span := trace.StartSpan(r.Context(), "beacon.QueryBeaconState")
	defer span.End()

	stateID := r.PathValue("state_id")
	if stateID == "" {
		httputil.HandleError(w, "state_id is required in URL params", http.StatusBadRequest)
		return
	}

	// Validate path before lookup: it might be expensive.
	var req structs.SSZQueryRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	switch {
	case errors.Is(err, io.EOF):
		httputil.HandleError(w, "No data submitted", http.StatusBadRequest)
		return
	case err != nil:
		httputil.HandleError(w, "Could not decode request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Query) == 0 {
		httputil.HandleError(w, "Empty query submitted", http.StatusBadRequest)
		return
	}

	path, err := query.ParsePath(req.Query)
	if err != nil {
		httputil.HandleError(w, "Could not parse path '"+req.Query+"': "+err.Error(), http.StatusBadRequest)
		return
	}

	stateRoot, err := s.Stater.StateRoot(ctx, []byte(stateID))
	if err != nil {
		var rootNotFoundErr *lookup.StateRootNotFoundError
		if errors.As(err, &rootNotFoundErr) {
			httputil.HandleError(w, "State root not found: "+rootNotFoundErr.Error(), http.StatusNotFound)
			return
		}
		httputil.HandleError(w, "Could not get state root: "+err.Error(), http.StatusInternalServerError)
		return
	}

	st, err := s.Stater.State(ctx, []byte(stateID))
	if err != nil {
		shared.WriteStateFetchError(w, err)
		return
	}

	// NOTE: Using unsafe conversion to proto is acceptable here,
	// as we play with a copy of the state returned by Stater.
	sszObject, ok := st.ToProtoUnsafe().(query.SSZObject)
	if !ok {
		httputil.HandleError(w, "Unsupported state version for querying: "+version.String(st.Version()), http.StatusBadRequest)
		return
	}

	info, err := query.AnalyzeObject(sszObject)
	if err != nil {
		httputil.HandleError(w, "Could not analyze state object: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, offset, length, err := query.CalculateOffsetAndLength(info, path)
	if err != nil {
		httputil.HandleError(w, "Could not calculate offset and length for path '"+req.Query+"': "+err.Error(), http.StatusInternalServerError)
		return
	}

	encodedState, err := st.MarshalSSZ()
	if err != nil {
		httputil.HandleError(w, "Could not marshal state to SSZ: "+err.Error(), http.StatusInternalServerError)
		return
	}

	result := encodedState[offset : offset+length]

	var response ssz.Marshaler
	if req.IncludeProof {
		proof, err := getBeaconStateProof(ctx, st, info, path)
		if err != nil {
			httputil.HandleError(w, "Could not compute merkle proofs for path "+req.Query+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		response = &sszquerypb.SSZQueryResponseWithProof{
			Root:   stateRoot,
			Result: result,
			Proof:  proof,
		}
	} else {
		response = &sszquerypb.SSZQueryResponse{
			Root:   stateRoot,
			Result: result,
		}
	}

	responseSsz, err := response.MarshalSSZ()
	if err != nil {
		httputil.HandleError(w, "Could not marshal response to SSZ: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(api.VersionHeader, version.String(st.Version()))
	httputil.WriteSsz(w, responseSsz)
}

// QueryBeaconState handles SSZ Query request for BeaconState.
// Returns as bytes serialized SSZQueryResponse.
func (s *Server) QueryBeaconBlock(w http.ResponseWriter, r *http.Request) {
	ctx, span := trace.StartSpan(r.Context(), "beacon.QueryBeaconBlock")
	defer span.End()

	blockId := r.PathValue("block_id")
	if blockId == "" {
		httputil.HandleError(w, "block_id is required in URL params", http.StatusBadRequest)
		return
	}

	// Validate path before lookup: it might be expensive.
	var req structs.SSZQueryRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	switch {
	case errors.Is(err, io.EOF):
		httputil.HandleError(w, "No data submitted", http.StatusBadRequest)
		return
	case err != nil:
		httputil.HandleError(w, "Could not decode request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Query) == 0 {
		httputil.HandleError(w, "Empty query submitted", http.StatusBadRequest)
		return
	}

	path, err := query.ParsePath(req.Query)
	if err != nil {
		httputil.HandleError(w, "Could not parse path '"+req.Query+"': "+err.Error(), http.StatusBadRequest)
		return
	}

	signedBlock, err := s.Blocker.Block(ctx, []byte(blockId))
	if !shared.WriteBlockFetchError(w, signedBlock, err) {
		return
	}

	protoBlock, err := signedBlock.Block().Proto()
	if err != nil {
		httputil.HandleError(w, "Could not convert block to proto: "+err.Error(), http.StatusInternalServerError)
		return
	}

	block, ok := protoBlock.(query.SSZObject)
	if !ok {
		httputil.HandleError(w, "Unsupported block version for querying: "+version.String(signedBlock.Version()), http.StatusBadRequest)
		return
	}

	info, err := query.AnalyzeObject(block)
	if err != nil {
		httputil.HandleError(w, "Could not analyze block object: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, offset, length, err := query.CalculateOffsetAndLength(info, path)
	if err != nil {
		httputil.HandleError(w, "Could not calculate offset and length for path '"+req.Query+"': "+err.Error(), http.StatusInternalServerError)
		return
	}

	encodedBlock, err := signedBlock.Block().MarshalSSZ()
	if err != nil {
		httputil.HandleError(w, "Could not marshal block to SSZ: "+err.Error(), http.StatusInternalServerError)
		return
	}

	blockRoot, err := block.HashTreeRoot()
	if err != nil {
		httputil.HandleError(w, "Could not compute block root: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := &sszquerypb.SSZQueryResponse{
		Root:   blockRoot[:],
		Result: encodedBlock[offset : offset+length],
	}

	responseSsz, err := response.MarshalSSZ()
	if err != nil {
		httputil.HandleError(w, "Could not marshal response to SSZ: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(api.VersionHeader, version.String(signedBlock.Version()))
	httputil.WriteSsz(w, responseSsz)
}

// getBeaconStateProof computes the merkle proof for the given path in the BeaconState.
// Optimized by using hybrid approach:
// - Leverage the native state's proof generation for anchor fields.
// - If needed, use generic proof collector for deeper fields, starting from the anchor.
func getBeaconStateProof(ctx context.Context, st state.BeaconState, info *query.SszInfo, path query.Path) (*sszquerypb.SSZQueryProof, error) {
	if len(path.Elements) == 0 {
		return nil, errors.New("cannot compute proof for empty path")
	}

	anchorField := path.Elements[0]
	anchorPath := query.Path{Elements: []query.PathElement{anchorField}}

	ci, err := info.ContainerInfo()
	if err != nil {
		return nil, fmt.Errorf("could not get container info: %w", err)
	}

	anchorSszInfo, err := ci.FieldInfo(anchorField.Name)
	if err != nil {
		return nil, fmt.Errorf("could not get field info for anchor field %q: %w", anchorField.Name, err)
	}

	anchorGindex, err := query.GetGeneralizedIndexFromPath(info, anchorPath)
	if err != nil {
		return nil, fmt.Errorf("could not compute gindex for anchor field %q: %w", anchorField.Name, err)
	}

	fieldIndex, ok := types.FieldIndexByName(anchorField.Name)
	if !ok {
		return nil, fmt.Errorf("unknown field name: %s", anchorField.Name)
	}

	anchorLeaf, topProofs, err := st.ProofByFieldIndex(ctx, fieldIndex)
	if err != nil {
		return nil, fmt.Errorf("could not compute proof for anchor field %q: %w", anchorField.Name, err)
	}

	if anchorField.Index != nil {
		// Accessing an element within a list/vector:
		// need to prepend element proofs.
		elementLeaf, elementProof, err := st.ProofForFieldElement(ctx, fieldIndex, uint64(*anchorField.Index))
		if err != nil {
			return nil, fmt.Errorf("could not compute proof for element %s[%d]: %w", anchorField.Name, *anchorField.Index, err)
		}

		anchorLeaf = elementLeaf

		switch anchorSszInfo.Type() {
		case query.List:
			// For list case, we need to mix-in the length hash.
			li, err := anchorSszInfo.ListInfo()
			if err != nil {
				return nil, fmt.Errorf("could not get list info for field %q: %w", anchorField.Name, err)
			}

			var lengthHash [32]byte
			binary.LittleEndian.PutUint64(lengthHash[:8], li.Length())

			topProofs = append([][]byte{lengthHash[:]}, topProofs...)

			// Re-set anchorSszInfo to the element type.
			anchorSszInfo, err = li.Element()
			if err != nil {
				return nil, fmt.Errorf("could not get element info for list field %q: %w", anchorField.Name, err)
			}

		case query.Vector:
			vi, err := anchorSszInfo.VectorInfo()
			if err != nil {
				return nil, fmt.Errorf("could not get vector info for field %q: %w", anchorField.Name, err)
			}

			// Re-set anchorSszInfo to the element type.
			anchorSszInfo, err = vi.Element()
			if err != nil {
				return nil, fmt.Errorf("could not get element info for vector field %q: %w", anchorField.Name, err)
			}

		default:
			return nil, fmt.Errorf("field %q is not a List or Vector, cannot access by index", anchorField.Name)
		}

		topProofs = append(elementProof, topProofs...)
	}

	if len(path.Elements) == 1 {
		// No deeper path, early return the top-level proof.
		return &sszquerypb.SSZQueryProof{
			Leaf:   anchorLeaf,
			Proofs: topProofs,
			Gindex: anchorGindex,
		}, nil
	}

	// Note: After this line, we now have to deepen the path from the anchor field.
	// A proof collector instance works generically for any SSZ object,
	// so we can use it to compute the deeper proof.

	targetGindex, err := query.GetGeneralizedIndexFromPath(info, path)
	if err != nil {
		return nil, fmt.Errorf("could not compute full gindex: %w", err)
	}

	relativeGindex, err := query.ComputeRelativeGindex(anchorGindex, targetGindex)
	if err != nil {
		return nil, fmt.Errorf("could not compute relative gindex from the anchor: %w", err)
	}

	bottomProof, err := anchorSszInfo.Prove(relativeGindex)
	if err != nil {
		return nil, fmt.Errorf("could not generate proof starting from the anchor field %q: %w", anchorField.Name, err)
	}

	return &sszquerypb.SSZQueryProof{
		Leaf: bottomProof.Leaf,
		// Note: proofs are sorted in decreasing order of gindex,
		Proofs: append(bottomProof.Hashes, topProofs...),
		Gindex: targetGindex,
	}, nil
}
