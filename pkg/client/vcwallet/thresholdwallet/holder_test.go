package thresholdwallet

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/internal/testdata"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	"github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/pbkdf2"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
)

const (
	sampleKeyServerURL = "sample/keyserver/test"
	sampleClientErr    = "sample client err"
	sampleCollectionID = "did:collection:1"
)

func TestCreateProfile(t *testing.T) {
	t.Run("test create new holder client using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleHolderID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NoError(t, ProfileExists(sampleHolderID, mockctx))

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)
	})

	t.Run("test create new holder client using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleHolderID, mockctx, wallet.WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)
		require.NoError(t, ProfileExists(sampleHolderID, mockctx))

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)
	})

	t.Run("test create new wallet client using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleHolderID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)
		require.NoError(t, ProfileExists(sampleHolderID, mockctx))

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)
	})

	t.Run("test create new wallet failure", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleHolderID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid create profile options")
		require.True(t, errors.Is(ProfileExists(sampleHolderID, mockctx), wallet.ErrProfileNotFound))

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.Error(t, err)
		require.Empty(t, holder)
	})

	t.Run("test create new wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		err := CreateProfile(sampleHolderID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.Error(t, err)
		require.Empty(t, holder)

		err = ProfileExists(sampleHolderID, mockctx)
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

		err := CreateProfile(sampleHolderID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.Error(t, err)
		require.Empty(t, holder)
	})

	t.Run("test create new wallet failure - create content store error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockStorageProvider{
			MockStoreProvider: mockstorage.NewMockStoreProvider(),
			failure:           fmt.Errorf(sampleClientErr),
		}

		err := CreateProfile(sampleHolderID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)
		require.Empty(t, holder)
	})
}

func TestUpdate(t *testing.T) {
	t.Run("test update wallet client using local kms passphrase", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleHolderID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)
	})

	t.Run("test update wallet client using local kms secret lock service", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleHolderID, mockctx, wallet.WithSecretLockService(&secretlock.MockSecretLock{}))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)
	})

	t.Run("test update wallet client using remote kms key server URL", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleHolderID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)
	})

	t.Run("test update wallet failure", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		err := UpdateProfile(sampleHolderID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid create profile options")

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)
	})

	t.Run("test update wallet failure - profile doesn't exists", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := UpdateProfile(sampleHolderID, mockctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.Error(t, err)
		require.Empty(t, holder)
	})

	t.Run("test update wallet failure - create store error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		err := UpdateProfile(sampleHolderID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.Error(t, err)
		require.Empty(t, holder)
	})

	t.Run("test update wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		createSampleProfile(t, mockctx)

		mockctx.StorageProviderValue.(*mockstorage.MockStoreProvider).Store.ErrPut = fmt.Errorf(sampleClientErr)

		err := UpdateProfile(sampleHolderID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleClientErr)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)
	})
}

func TestNewHolder(t *testing.T) {
	t.Run("test get client", func(t *testing.T) {
		mockctx := newMockProvider(t)
		// create a wallet
		err := CreateProfile(sampleHolderID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)
	})

	t.Run("test get client unlocked", func(t *testing.T) {
		mockctx := newMockProvider(t)
		// create a wallet
		err := CreateProfile(sampleHolderID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, holder)
	})

	t.Run("test get client unlock failure - wrong passphrase", func(t *testing.T) {
		mockctx := newMockProvider(t)
		// create a wallet
		err := CreateProfile(sampleHolderID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase+"ss"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
		require.Empty(t, holder)
	})

	t.Run("test get client by invalid userID", func(t *testing.T) {
		mockctx := newMockProvider(t)
		err := CreateProfile(sampleHolderID, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolderID+"invalid", SigningDelay, mockctx)
		require.Empty(t, holder)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")
	})

	t.Run("test update wallet failure - save profile error", func(t *testing.T) {
		mockctx := newMockProvider(t)
		mockctx.StorageProviderValue = &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleClientErr),
		}

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
		require.Error(t, err)
		require.Empty(t, holder)
		require.Contains(t, err.Error(), sampleClientErr)
	})
}

func TestHolder_OpenClose(t *testing.T) {
	t.Run("test open & close wallet using local kms passphrase", func(t *testing.T) {
		sampleHolder := uuid.New().String()
		mockctx := newMockProvider(t)

		err := CreateProfile(sampleHolder, mockctx, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolder, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)

		// get token
		err = holder.Open(wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)

		defer holder.Close()

		// try again
		err = holder.Open(wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.Error(t, err)
		require.True(t, errors.Is(err, wallet.ErrAlreadyUnlocked))

		// close wallet
		require.NoError(t, holder.Close())
		require.Error(t, holder.Close())

		// try to open with wrong passphrase
		err = holder.Open(wallet.WithUnlockByPassphrase(samplePassPhrase + "wrong"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
	})

	t.Run("test open & close wallet using secret lock service", func(t *testing.T) {
		sampleHolder := uuid.New().String()
		mockctx := newMockProvider(t)

		masterLock, err := pbkdf2.NewMasterLock(samplePassPhrase, sha256.New, 0, nil)
		require.NoError(t, err)

		err = CreateProfile(sampleHolder, mockctx, wallet.WithSecretLockService(masterLock))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolder, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)

		// get token
		err = holder.Open(wallet.WithUnlockBySecretLockService(masterLock))
		require.NoError(t, err)

		defer holder.Close()

		// try again
		err = holder.Open(wallet.WithUnlockBySecretLockService(masterLock))
		require.Error(t, err)
		require.True(t, errors.Is(err, wallet.ErrAlreadyUnlocked))

		// close wallet
		require.NoError(t, holder.Close())
		require.Error(t, holder.Close())

		// try to open with wrong secret lock service
		badLock, err := pbkdf2.NewMasterLock(samplePassPhrase+"wrong", sha256.New, 0, nil)
		require.NoError(t, err)

		err = holder.Open(wallet.WithUnlockBySecretLockService(badLock))
		require.Error(t, err)
		require.Contains(t, err.Error(), "message authentication failed")
	})

	t.Run("test open & close wallet using remote kms URL", func(t *testing.T) {
		sampleHolder := uuid.New().String()
		mockctx := newMockProvider(t)

		err := CreateProfile(sampleHolder, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolder, SigningDelay, mockctx)
		require.NoError(t, err)
		require.NotEmpty(t, holder)

		// get token
		err = holder.Open(wallet.WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
		require.NoError(t, err)

		defer holder.Close()

		// try again
		err = holder.Open(wallet.WithUnlockByAuthorizationToken(sampleRemoteKMSAuth))
		require.Error(t, err)
		require.True(t, errors.Is(err, wallet.ErrAlreadyUnlocked))

		// close wallet
		require.NoError(t, holder.Close())
		require.Error(t, holder.Close())
	})
}

func createSampleProfile(t *testing.T, mockctx *mockprovider.Provider) {
	t.Helper()

	err := CreateProfile(sampleHolderID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	holder, err := NewHolder(sampleHolderID, SigningDelay, mockctx)
	require.NoError(t, err)
	require.NotEmpty(t, holder)
}

func TestHolder_Store(t *testing.T) {
	mockctx := newMockProvider(t)
	err := CreateProfile(sampleHolderID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	holderClient, err := NewHolder(sampleHolderID, SigningDelay, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, holderClient)
	require.NoError(t, err)

	sampleCollectionID := fmt.Sprintf(CollectionIDTemplate, uuid.New().String())
	doc := NewDocument(Credential, testdata.SampleUDCVCWithProofBBS, sampleCollectionID)
	err = holderClient.Store(doc)
	require.NoError(t, err)

	// try locked wallet
	holderClient, err = NewHolder(sampleHolderID, SigningDelay, mockctx)
	require.NotEmpty(t, holderClient)
	require.NoError(t, err)

	err = holderClient.Store(doc)
	require.Contains(t, err.Error(), "wallet locked")
}

func TestHolder_Get(t *testing.T) {
	mockctx := newMockProvider(t)
	err := CreateProfile(sampleHolderID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	holderClient, err := NewHolder(sampleHolderID, SigningDelay, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, holderClient)
	require.NoError(t, err)

	credDoc, err := documentFromCredential(testdata.SampleUDCVC, sampleCollectionID)
	require.NoError(t, err)
	err = holderClient.Store(credDoc)
	require.NoError(t, err)

	doc, err := holderClient.Get(Credential, "http://example.edu/credentials/1872", sampleCollectionID)
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
	require.NoError(t, holderClient.Close())
	doc, err = holderClient.Get(Credential, "http://example.edu/credentials/1872", sampleCollectionID)
	require.Error(t, err)
	require.Empty(t, doc)
}

func TestHolder_GetCollection(t *testing.T) {
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
	err := CreateProfile(sampleHolderID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	holderClient, err := NewHolder(sampleHolderID, SigningDelay, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, holderClient)
	require.NoError(t, err)

	// save a collection
	require.NoError(t, holderClient.AddCollection(sampleCollectionID))

	// save test data
	const count = 5

	for i := 0; i < count; i++ {
		cred, err := documentFromCredential([]byte(fmt.Sprintf(vcContent, uuid.New().String())), sampleCollectionID)
		require.NoError(t, err)
		require.NoError(t, holderClient.Store(cred))
	}

	// get all by content
	vcs, err := holderClient.GetCollection(sampleCollectionID)
	require.NoError(t, err)
	require.Len(t, vcs, count)

	// try locked wallet
	require.NoError(t, holderClient.Close())
	vcs, err = holderClient.GetCollection(sampleCollectionID)
	require.Error(t, err)
	require.Empty(t, vcs)
}

func TestHolder_Remove(t *testing.T) {
	mockctx := newMockProvider(t)
	err := CreateProfile(sampleHolderID, mockctx, wallet.WithKeyServerURL(sampleKeyServerURL))
	require.NoError(t, err)

	holderClient, err := NewHolder(sampleHolderID, SigningDelay, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, holderClient)
	require.NoError(t, err)

	credDoc, err := documentFromCredential(testdata.SampleUDCVC, sampleCollectionID)
	require.NoError(t, err)
	err = holderClient.Store(credDoc)
	require.NoError(t, err)

	content, err := holderClient.Get(Credential, "http://example.edu/credentials/1872", sampleCollectionID)
	require.NoError(t, err)
	require.NotEmpty(t, content)

	err = holderClient.Remove(Credential, "http://example.edu/credentials/1872")
	require.NoError(t, err)

	content, err = holderClient.Get(Credential, "http://example.edu/credentials/1872", sampleCollectionID)
	require.Empty(t, content)
	require.Error(t, err)

	// try locked wallet
	require.NoError(t, holderClient.Close())
	err = holderClient.Remove(Credential, "http://example.edu/credentials/1872")
	require.Error(t, err)
}

func TestHolder_RemoveCollection(t *testing.T) {
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
	err := CreateProfile(sampleHolderID, mockctx, wallet.WithPassphrase(samplePassPhrase))
	require.NoError(t, err)

	holderClient, err := NewHolder(sampleHolderID, SigningDelay, mockctx, wallet.WithUnlockByPassphrase(samplePassPhrase))
	require.NotEmpty(t, holderClient)
	require.NoError(t, err)

	// save a collection
	require.NoError(t, holderClient.AddCollection(sampleCollectionID))

	// save test data
	const count = 5

	for i := 0; i < count; i++ {
		cred, err := documentFromCredential([]byte(fmt.Sprintf(vcContent, uuid.New().String())), sampleCollectionID)
		require.NoError(t, err)
		require.NoError(t, holderClient.Store(cred))
	}

	// get all by content
	vcs, err := holderClient.GetCollection(sampleCollectionID)
	require.NoError(t, err)
	require.Len(t, vcs, count)

	// remove collection
	err = holderClient.RemoveCollection(sampleCollectionID)
	require.NoError(t, err)

	vcs, err = holderClient.GetCollection(sampleCollectionID)
	require.NoError(t, err)
	require.Empty(t, vcs)

	// try locked wallet
	require.NoError(t, holderClient.Close())
	vcs, err = holderClient.GetCollection(sampleCollectionID)
	require.Error(t, err)
	require.Empty(t, vcs)
}

type mockStorageProvider struct {
	*mockstorage.MockStoreProvider
	config  storage.StoreConfiguration
	failure error
}

func (s *mockStorageProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	s.config = config

	return s.failure
}

func (s *mockStorageProvider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	return s.config, nil
}
