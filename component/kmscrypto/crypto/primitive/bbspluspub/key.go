package bbspluspub

import (
	"crypto/rand"
	"errors"
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/helper"
	"github.com/perun-network/bbs-plus-threshold-wallet/precomputation"

	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
)

var (
	// nolint:gochecknoglobals
	seedSize = helper.LenBytesFr

	// nolint:gochecknoglobals
	generateKeySalt = "BBS-SIG-KEYGEN-SALT-"
)

type BBSPlusPubKey struct {
	*fhks_bbs_plus.PublicKey
}

type BBSPlusPrivKey struct {
	*fhks_bbs_plus.SecretKey
}

func GenerateKeyPair(h func() hash.Hash, seed []byte, t, n, k int) (*BBSPlusPubKey, *BBSPlusPrivKey, []*fhks_bbs_plus.PerPartyPrecomputationsWithPubKey, error) {
	if len(seed) != 0 && len(seed) != seedSize {
		return nil, nil, nil, errors.New("invalid size of seed")
	}

	okm, err := generateOKM(seed, h)
	if err != nil {
		return nil, nil, nil, err
	}

	sk := fhks_bbs_plus.SecretKey{}
	sk.Deserialize(okm)

	privKey := &fhks_bbs_plus.SecretKey{Fr: sk.Fr}
	pubKey := privKey.GetPublicKey(k)
	// output := helper.GetShamirSharedRandomElementFromSecretKey(privKey.Fr, t, n)
	output := precomputation.GeneratePCFPCGOutputMockedFromSecretKey(privKey.Fr, t, k, n)
	precomputations := precomputation.CreatePPPrecomputationFromVOLEEvaluationWithPubKey(k, n,
		pubKey.W,
		output.SkShares,
		output.AShares,
		output.EShares,
		output.SShares,
		output.AeTerms,
		output.AsTerms,
		output.AskTerms,
	)

	return &BBSPlusPubKey{pubKey}, &BBSPlusPrivKey{privKey}, precomputations, nil
}

func generateOKM(ikm []byte, h func() hash.Hash) ([]byte, error) {
	salt := []byte(generateKeySalt)
	info := make([]byte, 2)

	if ikm != nil {
		ikm = append(ikm, 0)
	} else {
		ikm = make([]byte, seedSize+1)

		_, err := rand.Read(ikm)
		if err != nil {
			return nil, err
		}

		ikm[seedSize] = 0
	}

	return newHKDF(h, ikm, salt, info, helper.LenBytesFr)
}

func newHKDF(h func() hash.Hash, ikm, salt, info []byte, length int) ([]byte, error) {
	reader := hkdf.New(h, ikm, salt, info)
	result := make([]byte, length)

	_, err := io.ReadFull(reader, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
