package signer

import (
	"errors"
	"strings"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbsplusthresholdpub"
)

// baseSignatureSigner defines a base signature signer.
type baseSignatureSigner struct {
	keyType   string
	curve     string
	algorithm string
}

func (sv baseSignatureSigner) KeyType() string {
	return sv.keyType
}

func (sv baseSignatureSigner) Curve() string {
	return sv.curve
}

func (sv baseSignatureSigner) Algorithm() string {
	return sv.algorithm
}

// ThresholdBBSG2SignaturePartySigner defines a party signer based on the baseSignatureSigner.
// Party signer signs a credential and produces a partial signature based on its pregenerated presignature.
type ThresholdBBSG2SignaturePartySigner struct {
	partyPrivKeyBytes []byte

	indices [][]int // Indices indicates participating parties and their order in threshold signing.
	// Needed for creating partial signature. Determined by the Holder.
	// 1.Dimension is the index of the presignatures to be used. 2.Dimension is the index of the participating party.

	presignatures []*bbsplusthresholdpub.PerPartyPresignature
	msgIndex      int // Index of the current message/presignature.
	baseSignatureSigner
}

// NewThresholdBBSG2SignaturePartySigner creates a new instance of a Party Signer given its precomputation.
func NewThresholdBBSG2SignaturePartySigner(precomputationBytes []byte) (*ThresholdBBSG2SignaturePartySigner, error) {
	precomputation, err := bbsplusthresholdpub.ParsePerPartyPrecomputations(precomputationBytes)
	if err != nil {
		return nil, err
	}
	partyPrivKey := precomputation.PartyPrivateKey()
	partyPrivKeyBytes, err := partyPrivKey.Marshal()
	if err != nil {
		return nil, err
	}
	numOfPresigs := len(precomputation.Presignatures)
	return &ThresholdBBSG2SignaturePartySigner{
		partyPrivKeyBytes: partyPrivKeyBytes,
		indices:           make([][]int, numOfPresigs),
		presignatures:     precomputation.Presignatures,
		baseSignatureSigner: baseSignatureSigner{
			keyType:   "EC",
			curve:     "BLS12381_G2",
			algorithm: "party_threshold_bbs+",
		},
	}, nil
}

func (tbps *ThresholdBBSG2SignaturePartySigner) SetIndices(indices []int, index int) {
	tbps.indices[index] = indices
}

func (tbps *ThresholdBBSG2SignaturePartySigner) SetNexMsgIndex(msgIndex int) {
	tbps.msgIndex = msgIndex
}

func (tbps *ThresholdBBSG2SignaturePartySigner) Alg() string {
	return tbps.Algorithm()
}

// Sign will sign create a partial signature of each message and aggregate it
// into a single partial signature using the signer's precomputation.
// returns:
//
//	partial signature in []byte
//	error in case of errors
func (tbps *ThresholdBBSG2SignaturePartySigner) Sign(data []byte) ([]byte, error) {
	party_bbs := bbsplusthresholdpub.New()
	if tbps.msgIndex >= len(tbps.presignatures) || tbps.msgIndex < 0 {
		return nil, errors.New("out of presignatures")
	}
	if tbps.indices[tbps.msgIndex] == nil {
		return nil, errors.New("missing indices")
	}
	partialSigBytes, err := party_bbs.SignWithPresignature(splitMessageIntoLines(string(data)),
		tbps.partyPrivKeyBytes,
		tbps.indices[tbps.msgIndex],
		tbps.presignatures[tbps.msgIndex])
	if err != nil {
		return nil, err
	}
	return partialSigBytes, nil
}

// ThresholdBBSG2SignatureSigner defines a Signer based on the Threshold BBS+ Signature Scheme.
// The signer produces a threshold signature based on the partial signature of the credential.
type ThresholdBBSG2SignatureSigner struct {
	threshold         int
	msgIndex          int
	partialSignatures [][]byte
	baseSignatureSigner
}

// NewThresholdBBSG2SignatureSigner creates a new instance of a Threshold Signer.
// Args:
//   - threshold: the t-out-of-n number determined as the precompuations were generated.
//   - msgIndex: the next in-line index of the message to be signed.
//   - partialSignatures: partial signatures of the credential in bytes.
func NewThresholdBBSG2SignatureSigner(threshold, msgIndex int,
	partialSignatures [][]byte) *ThresholdBBSG2SignatureSigner {
	return &ThresholdBBSG2SignatureSigner{
		threshold:         threshold,
		msgIndex:          msgIndex,
		partialSignatures: partialSignatures,
		baseSignatureSigner: baseSignatureSigner{
			keyType:   "EC",
			curve:     "BLS12381_G2",
			algorithm: "main_threshold_bbs+",
		},
	}
}

// Signs produces a threshold signatures based on its partial signatures.
func (tbs *ThresholdBBSG2SignatureSigner) Sign(data []byte) ([]byte, error) {
	main_bbs := bbsplusthresholdpub.New()
	sigBytes, err := main_bbs.SignWithPartialSignatures(tbs.partialSignatures)
	if err != nil {
		return nil, err
	}
	return sigBytes, nil
}

func (tbs *ThresholdBBSG2SignatureSigner) Alg() string {
	return tbs.Algorithm()
}

func splitMessageIntoLines(msg string) [][]byte {
	rows := strings.Split(msg, "\n")

	msgs := make([][]byte, 0, len(rows))

	for _, row := range rows {
		if strings.TrimSpace(row) == "" {
			continue
		}

		msgs = append(msgs, []byte(row))
	}

	return msgs
}
