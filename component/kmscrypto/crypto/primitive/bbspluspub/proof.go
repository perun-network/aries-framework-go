package bbspluspub

import (
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"
)

// DeriveProof derives a proof of BBS+ signature with some messages disclosed.
func (bbs *BBSPlusPub) DeriveProof(messages [][]byte, sigBytes, nonce, pubKeyBytes []byte, revealedIndexes []int) ([]byte, error) {
	return zkp.CreateProofBBS(messages, sigBytes, nonce, pubKeyBytes, revealedIndexes)

}

// VerifyProof verifies BBS+ signature proof for one ore more revealed messages.
func (bbs *BBSPlusPub) VerifyProof(messagesBytes [][]byte, proof, nonce, pubKeyBytes []byte) error {

	return zkp.VerifyBBSProof(messagesBytes, proof, nonce, pubKeyBytes)

}
