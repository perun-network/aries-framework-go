package thresholdwallet

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/internal/testdata"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/pbkdf2"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/stretchr/testify/require"
)

var (
	signerID = fmt.Sprintf(sampleSignerID, 0)
)

func TestSignerCreateProfile(t *testing.T) {
	t.Run("test create new signer client using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(fmt.Sprintf(signerID, 0), mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NoError(t, ProfileExists(signerID, mockctx))

		signer, err := NewPartySigner(signerID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)
	})

	t.Run("test create new signer client using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(signerID, mockctx, wallet.WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)
		require.NoError(t, ProfileExists(signerID, mockctx))

		signer, err := NewPartySigner(signerID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)
	})

	t.Run("test create new wallet client using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(signerID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)
		require.NoError(t, ProfileExists(signerID, mockctx))

		signer, err := NewPartySigner(signerID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)
	})

	t.Run("test create new wallet failure", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(signerID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid create profile options")
		require.True(t, errors.Is(ProfileExists(signerID, mockctx), wallet.ErrProfileNotFound))

		signer, err := NewPartySigner(signerID, mockctx)
		require.Error(t, err)
		require.Empty(t, signer)
	})

	t.Run("test create new wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		err := CreateProfile(signerID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		signer, err := NewPartySigner(signerID, mockctx)
		require.Error(t, err)
		require.Empty(t, signer)

		err = ProfileExists(signerID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)
	})

	t.Run("test create new wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				ErrPut: fmt.Errorf(sampleClientErr),
			},
		}

		err := CreateProfile(signerID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		signer, err := NewPartySigner(signerID, mockctx)
		require.Error(t, err)
		require.Empty(t, signer)
	})

	t.Run("test create new wallet failure - create content store error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockStorageProvider{
			MockStoreProvider: mockstorage.NewMockStoreProvider(),
			failure:           fmt.Errorf(sampleClientErr),
		}

		err := CreateProfile(signerID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		signer, err := NewPartySigner(signerID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)
		require.Empty(t, signer)
	})
}

func TestSignerUpdate(t *testing.T) {
	t.Run("test update wallet client using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(signerID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		signer, err := NewPartySigner(signerID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)
	})

	t.Run("test update wallet client using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(signerID, mockctx, wallet.WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)

		signer, err := NewPartySigner(signerID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)
	})

	t.Run("test update wallet client using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(signerID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		signer, err := NewPartySigner(signerID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)
	})

	t.Run("test update wallet failure", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(signerID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid create profile options")

		signer, err := NewPartySigner(signerID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)
	})

	t.Run("test update wallet failure - profile doesn't exists", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := UpdateProfile(signerID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")

		signer, err := NewPartySigner(signerID, mockctx)
		require.Error(t, err)
		require.Empty(t, signer)
	})

	t.Run("test update wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		err := UpdateProfile(signerID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		signer, err := NewPartySigner(signerID, mockctx)
		require.Error(t, err)
		require.Empty(t, signer)
	})

	t.Run("test update wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		mockctx.StorageProviderValue.(*mockstorage.MockStoreProvider).Store.ErrPut = fmt.Errorf(sampleClientErr)

		err := UpdateProfile(signerID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		signer, err := NewPartySigner(signerID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)
	})
}

func TestNewPartySigner(t *testing.T) {
	t.Run("test get client", func(t *testing.T) {
		mockctx := newMockProvider(t)
		// create a wallet
		err := CreateProfile(signerID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		signer, err := NewPartySigner(signerID, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)
	})

	t.Run("test get client unlocked", func(t *testing.T) {
		mockctx := newMockProvider(t)
		// create a wallet
		err := CreateProfile(signerID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		signer, err := NewPartySigner(signerID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, signer)
	})

	t.Run("test get client unlock failure - wrong passphrase", func(t *testing.T) {
		mockctx := newMockProvider(t)
		// create a wallet
		err := CreateProfile(signerID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		signer, err := NewPartySigner(signerID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase+"ss"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
		require.Empty(t, signer)
	})

	t.Run("test get client by invalid userID", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(signerID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		signer, err := NewPartySigner(signerID+"invalid", mockctx)
		require.Empty(t, signer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")
	})

	t.Run("test update wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		signer, err := NewPartySigner(signerID, mockctx)
		require.Error(t, err)
		require.Empty(t, signer)
		require.Contains(t, err.Error(), sampleClientErr)
	})
}

func TestSigner_OpenClose(t *testing.T) {
	t.Run("test open & close wallet using local kms passphrase", func(t *testing.T) {
		sampleSigner := uuid.New().String()
		mockctx := newMockProvider(t)

		err := CreateProfile(sampleSigner, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		signer, err := NewPartySigner(sampleSigner, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)

		// get token
		err = signer.Open(wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)

		defer signer.Close()

		// try again
		err = signer.Open(wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.Error(t, err)
		require.True(t, errors.Is(err, wallet.ErrAlreadyUnlocked))

		// close wallet
		require.NoError(t, signer.Close())
		require.Error(t, signer.Close())

		// try to open with wrong passphrase
		err = signer.Open(wallet.WithUnlockByPassphrase(samplePassPhrase + "wrong"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
	})

	t.Run("test open & close wallet using secret lock service", func(t *testing.T) {
		sampleSigner := uuid.New().String()
		mockctx := newMockProvider(t)

		masterLock, err := pbkdf2.NewMasterLock(samplePassPhrase, sha256.New, 0, nil)
		require.NoError(t, err)

		err = CreateProfile(sampleSigner, mockctx, wallet.WithSecretLockService(masterLock))
		require.NoError(t, err)

		signer, err := NewPartySigner(sampleSigner, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)

		// get token
		err = signer.Open(wallet.WithUnlockBySecretLockService(masterLock))
		require.NoError(t, err)

		defer signer.Close()

		// try again
		err = signer.Open(wallet.WithUnlockBySecretLockService(masterLock))
		require.Error(t, err)
		require.True(t, errors.Is(err, wallet.ErrAlreadyUnlocked))

		// close wallet
		require.NoError(t, signer.Close())
		require.Error(t, signer.Close())

		// try to open with wrong secret lock service
		badLock, err := pbkdf2.NewMasterLock(samplePassPhrase+"wrong", sha256.New, 0, nil)
		require.NoError(t, err)

		err = signer.Open(wallet.WithUnlockBySecretLockService(badLock))
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
	})

	t.Run("test open & close wallet using remote kms URL", func(t *testing.T) {
		sampleSigner := uuid.New().String()
		mockctx := newMockProvider(t)

		err := CreateProfile(sampleSigner, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		signer, err := NewPartySigner(sampleSigner, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, signer)

		// get token
		err = signer.Open(wallet.WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
		require.NoError(t, err)

		defer signer.Close()

		// try again
		err = signer.Open(wallet.WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
		require.Error(t, err)
		require.True(t, errors.Is(err, wallet.ErrAlreadyUnlocked))

		// close wallet
		require.NoError(t, signer.Close())
		require.Error(t, signer.Close())
	})
}

func TestSigner_Store(t *testing.T) {
	mockctx := newMockProvider(t)
	err := CreateProfile(signerID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	signerClient, err := NewPartySigner(signerID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, signerClient)
	require.NoError(t, err)

	sampleCollectionID := fmt.Sprintf(CollectionIDTemplate, uuid.New().String())
	doc := NewDocument(Credential, testdata.SampleUDCVCWithProofBBS, sampleCollectionID)
	err = signerClient.Store(doc)
	require.NoError(t, err)

	// try locked wallet
	signerClient, err = NewPartySigner(signerID, mockctx)
	require.NotEmpty(t, signerClient)
	require.NoError(t, err)

	err = signerClient.Store(doc)
	require.Contains(t, err.Error(), "wallet locked")
}

func TestSigner_Get(t *testing.T) {
	mockctx := newMockProvider(t)
	err := CreateProfile(signerID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	signerClient, err := NewPartySigner(signerID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, signerClient)
	require.NoError(t, err)

	credDoc, err := documentFromCredential(testdata.SampleUDCVC, sampleCollectionID)
	require.NoError(t, err)
	err = signerClient.Store(credDoc)
	require.NoError(t, err)

	doc, err := signerClient.Get(Credential, "http://example.edu/credentials/1872", sampleCollectionID)
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	cred, err := verifiable.ParseCredential(doc.Content, verifiable.WithCredDisableValidation())
	require.NoError(t, err)
	credBytes, err := cred.MarshalJSON()
	require.NoError(t, err)

	testCred, err := verifiable.ParseCredential(testdata.SampleUDCVC, verifiable.WithCredDisableValidation())
	require.NoError(t, err)
	testCredBytes, err := testCred.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, string(testCredBytes), string(credBytes))

	// try locked wallet
	require.NoError(t, signerClient.Close())
	doc, err = signerClient.Get(Credential, "http://example.edu/credentials/1872", sampleCollectionID)
	require.Error(t, err)
	require.Empty(t, doc)
}

func TestSigner_GetCollection(t *testing.T) {
	const vcContent = `{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "%s",
      "issuer": {
        "id": "did:example:76e12ec712ebc6f1c221ebfeb1f"
      },
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ]
    }`
	mockctx := newMockProvider(t)
	err := CreateProfile(signerID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	signerClient, err := NewPartySigner(signerID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, signerClient)
	require.NoError(t, err)

	// save a collection
	require.NoError(t, signerClient.AddCollection(sampleCollectionID))

	// save test data
	const count = 5

	for i := 0; i < count; i++ {
		cred, err := documentFromCredential([]byte(fmt.Sprintf(vcContent, uuid.New().String())), sampleCollectionID)
		require.NoError(t, err)
		require.NoError(t, signerClient.Store(cred))
	}

	// get all by content
	vcs, err := signerClient.GetCollection(sampleCollectionID)
	require.NoError(t, err)
	require.Len(t, vcs, count)

	// try locked wallet
	require.NoError(t, signerClient.Close())
	vcs, err = signerClient.GetCollection(sampleCollectionID)
	require.Error(t, err)
	require.Empty(t, vcs)
}

func TestSigner_Remove(t *testing.T) {
	mockctx := newMockProvider(t)
	err := CreateProfile(signerID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	signerClient, err := NewPartySigner(signerID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, signerClient)
	require.NoError(t, err)

	credDoc, err := documentFromCredential(testdata.SampleUDCVC, sampleCollectionID)
	require.NoError(t, err)
	err = signerClient.Store(credDoc)
	require.NoError(t, err)

	content, err := signerClient.Get(Credential, "http://example.edu/credentials/1872", sampleCollectionID)
	require.NoError(t, err)
	require.NotEmpty(t, content)

	err = signerClient.Remove(Credential, "http://example.edu/credentials/1872")
	require.NoError(t, err)

	content, err = signerClient.Get(Credential, "http://example.edu/credentials/1872", sampleCollectionID)
	require.Empty(t, content)
	require.Error(t, err)

	// try locked wallet
	require.NoError(t, signerClient.Close())
	err = signerClient.Remove(Credential, "http://example.edu/credentials/1872")
	require.Error(t, err)
}

func TestSigner_RemoveCollection(t *testing.T) {
	const vcContent = `{
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "%s",
      "issuer": {
        "id": "did:example:76e12ec712ebc6f1c221ebfeb1f"
      },
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ]
    }`
	mockctx := newMockProvider(t)
	err := CreateProfile(signerID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	signerClient, err := NewPartySigner(signerID, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, signerClient)
	require.NoError(t, err)

	// save a collection
	require.NoError(t, signerClient.AddCollection(sampleCollectionID))

	// save test data
	const count = 5

	for i := 0; i < count; i++ {
		cred, err := documentFromCredential([]byte(fmt.Sprintf(vcContent, uuid.New().String())), sampleCollectionID)
		require.NoError(t, err)
		require.NoError(t, signerClient.Store(cred))
	}

	// get all by content
	vcs, err := signerClient.GetCollection(sampleCollectionID)
	require.NoError(t, err)
	require.Len(t, vcs, count)

	// remove collection
	err = signerClient.RemoveCollection(sampleCollectionID)
	require.NoError(t, err)

	vcs, err = signerClient.GetCollection(sampleCollectionID)
	require.NoError(t, err)
	require.Empty(t, vcs)

	// try locked wallet
	require.NoError(t, signerClient.Close())
	vcs, err = signerClient.GetCollection(sampleCollectionID)
	require.Error(t, err)
	require.Empty(t, vcs)
}
