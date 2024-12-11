package test

import (
	"github.com/perun-network/bbs-plus-threshold-wallet/fhks_bbs_plus"
	"github.com/perun-network/bbs-plus-threshold-wallet/zkp/test"

	"testing"
)

type KeyPairTest struct {
	SecretKey fhks_bbs_plus.SecretKey
	PublicKey fhks_bbs_plus.PublicKey
}

func SetupKeyPairTest(t *testing.T, msgCount int) KeyPairTest {
	kp := test.CreateTestingKP(t, msgCount)

	return KeyPairTest{SecretKey: kp.SecretKey, PublicKey: kp.PublicKey}

}
