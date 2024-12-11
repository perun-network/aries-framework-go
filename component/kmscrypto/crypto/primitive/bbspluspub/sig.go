package bbspluspub

import (
	"errors"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"
)

// SignWithPartialSignatures produces a threshold signature given the partial signatures in bytes.
func (bbs *BBSPlusPub) SignWithPartialSignatures(partialSignaturesBytes [][]byte) ([]byte, error) {

	partialSignatures := make([]*fhks_bbs_plus.PartialThresholdSignature, len(partialSignaturesBytes))

	for _, partSigBytes := range partialSignaturesBytes {
		partialSignature, err := fhks_bbs_plus.PartThreshSigFromBytes(partSigBytes) //ParsePartialSignature(partialSignatureBytes)
		if err != nil {
			return nil, err
		}
		partialSignatures = append(partialSignatures, partialSignature)
	}

	thresholdSig := fhks_bbs_plus.ThresholdSignature{}
	thresholdSig.FromPartialSignatures(partialSignatures)

	return thresholdSig.ToBytes()
}

// SignWithPresignature produces a partial signature for messages using a Threshold BBS+ presignature.
func (*BBSPlusPub) SignWithPresignature(
	messages [][]byte,
	partyPrivKey []byte,
	indices []int,
	presignature *fhks_bbs_plus.PerPartyPreSignature) ([]byte, error) {

	partySecretKey, err := fhks_bbs_plus.UnmarshalPartyPrivateKey(partyPrivKey)
	if err != nil {
		return nil, err
	}

	skFr := partySecretKey.SKeyShare.Fr

	sk := fhks_bbs_plus.SecretKey{Fr: skFr}

	pubKey := sk.GetPublicKey(len(messages))

	messagesCount := len(messages)

	if messagesCount == 0 {
		return nil, errors.New("messages are not defined")
	}

	messagesFr := zkp.ByteMsgToFr(messages)

	livePresignature := fhks_bbs_plus.NewLivePreSignature()
	livePresignature.FromPreSignature(partySecretKey.Index+1, indices, presignature)

	partSignature := fhks_bbs_plus.NewPartialThresholdSignature().New(
		messagesFr,
		pubKey,
		livePresignature,
	)

	return partSignature.ToBytes()
}
