package bbspluspub

import (
	"errors"
	"fmt"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp"
)

type BBSPlusPub struct{}

// New creates a new BBSPlusPub.
func New() *BBSPlusPub {
	return &BBSPlusPub{}
}

// Verify makes BLS BBS12-381 signature verification.
func (bbs *BBSPlusPub) Verify(messages [][]byte, sigBytes, pubKeyBytes []byte) (bool, error) {
	signature, err := fhks_bbs_plus.ThresholdSignatureFromBytes(sigBytes) //ParseSignature(sigBytes)
	if err != nil {
		return false, fmt.Errorf("parse signature: %w", err)
	}

	pubKey, err := fhks_bbs_plus.DeserializePublicKey(pubKeyBytes) //UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}

	messagesFr := zkp.ByteMsgToFr(messages) //messagesToFr(messages)

	return signature.Verify(messagesFr, pubKey), nil
}

// Sign signs the one or more messages using private key in compressed form.
func (bbs *BBSPlusPub) Sign(messages [][]byte, privKeyBytes []byte) ([]byte, error) {
	sk := fhks_bbs_plus.SecretKey{}
	err := sk.Deserialize(privKeyBytes) ////--UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}

	msgCount := len(messages)

	if len(messages) == 0 {
		return nil, errors.New("messages are not defined")
	}

	e := fhks_bbs_plus.GenerateRandomFr()
	s := fhks_bbs_plus.GenerateRandomFr()

	frMsgs := zkp.ByteMsgToFr(messages)
	pubkey := *sk.GetPublicKey(msgCount)

	signature := sk.Sign(pubkey, frMsgs, e, s)
	sigBytes, err := signature.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("signature to bytes: %w", err)
	}

	return sigBytes, nil
}
