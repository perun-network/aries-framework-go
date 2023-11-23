package thresholdwallet

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/stretchr/testify/require"

	issuecredentialsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	outofbandSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	presentproofSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	mockoutofbandv2 "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/outofbandv2"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockissuecredential "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/issuecredential"
	mockmediator "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockoutofband "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/outofband"
	mockpresentproof "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/presentproof"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const (
	sampleHolderID = "sample-holder"
	sampleSignerID = "sample-signer%d"

	externalPrefix = "http://"
	endpointHolder = "localhost:26709"
	endpointSigner = "localhost:2670%d"

	samplePassPhrase    = "fakepassphrase"
	sampleRemoteKMSAuth = "sample-auth-token"

	threshold = 3 // threshold number t (-out of n)
	n         = 5 // number of participating servers
	k         = 1 // number of generated precomputations

)

func TestIssueThresholdCredential(t *testing.T) {
	vcJSON := `
	{
	 "@context": [
	   "https://www.w3.org/2018/credentials/v1",
	   "https://w3id.org/citizenship/v1",
	   "https://w3id.org/security/bbs/v1"
	 ],
	 "id": "did:credential:urn:uuid:b8d89593-c7de-4aa6-a126-89879367c76e",
	 "type": [
	   "VerifiableCredential",
	   "PermanentResidentCard"
	 ],
	 "issuer": "did:example:489398593",
	 "identifier": "83627465",
	 "name": "Permanent Resident Card",
	 "description": "Government of Example Permanent Resident Card.",
	 "issuanceDate": "2019-12-03T12:19:52Z",
	 "expirationDate": "2029-12-03T12:19:52Z",
	 "credentialSubject": {
	   "id": "did:example:b34ca6cd37bbf23",
	   "type": [
	     "PermanentResident",
	     "Person"
	   ],
	   "givenName": "JOHN",
	   "familyName": "SMITH",
	   "gender": "Male",
	   "image": "data:image/png;base64,iVBORw0KGgokJggg==",
	   "residentSince": "2015-01-01",
	   "lprCategory": "C09",
	   "lprNumber": "999-999-999",
	   "commuterClassification": "C1",
	   "birthCountry": "Bahamas",
	   "birthDate": "1958-07-17"
	 }
	}
	`
	t.Run("test simple issue credential protocol between holder and partial signers", func(t *testing.T) {
		// Init Holder's wallet.
		inboundHolder, err := http.NewInbound(endpointHolder, externalPrefix+endpointHolder, "", "")
		require.NoError(t, err)

		documentLoader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)
		holderAries, err := aries.New(aries.WithInboundTransport(inboundHolder), aries.WithJSONLDDocumentLoader(documentLoader))
		require.NoError(t, err)

		mockctxHolder, err := holderAries.Context()
		require.NoError(t, err)

		err = CreateProfile(sampleHolderID, mockctxHolder, wallet.WithPassphrase(samplePassPhrase))
		require.NoError(t, err)

		holder, err := NewHolder(sampleHolderID, SigningDelay, mockctxHolder, wallet.WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotNil(t, holder)

		err = holder.DefaultHandler()
		require.NoError(t, err)

		// Init Precomputation's generator.
		thresholdbbsplusGenerator := NewThresholdBBSPlusGenerator()
		seed := make([]byte, 32)
		_, err = rand.Read(seed)
		require.NoError(t, err)

		collectionID, publicKeyDoc, precomputationDocs, err := thresholdbbsplusGenerator.GeneratePrecomputation(sha256.New, seed, threshold, n, k)
		require.NoError(t, err)

		err = holder.AddCollection(collectionID)
		require.NoError(t, err)

		// Init Party Signers' wallets.
		signers := make([]Wallet, n)
		for i := 0; i < n; i++ {
			inboundSigner, err := http.NewInbound(fmt.Sprintf(endpointSigner, i), externalPrefix+fmt.Sprintf(endpointSigner, i), "", "")
			require.NoError(t, err)

			documentLoader, err := ldtestutil.DocumentLoader()
			require.NoError(t, err)
			signerAries, err := aries.New(aries.WithInboundTransport(inboundSigner), aries.WithJSONLDDocumentLoader(documentLoader))
			require.NoError(t, err)

			mockctxSigner, err := signerAries.Context()
			require.NoError(t, err)

			err = CreateProfile(fmt.Sprintf(sampleSignerID, i), mockctxSigner, wallet.WithPassphrase(samplePassPhrase))
			require.NoError(t, err)
			signers[i], err = NewPartySigner(fmt.Sprintf(sampleSignerID, i), mockctxSigner, wallet.WithUnlockByPassphrase(samplePassPhrase))
			require.NoError(t, err)
			require.NotNil(t, signers[i])

			err = signers[i].DefaultHandler()
			require.NoError(t, err)

			invitation, err := signers[i].Invite(signerID)
			require.NoError(t, err)

			_, err = holder.Connect(invitation)
			require.NoError(t, err)

			connection, err := holder.GetConnection(invitation.ID)
			require.NoError(t, err)

			// holder adds contacts of signers.
			err = holder.AddPartySigner(collectionID, connection)
			require.NoError(t, err)
		}

		for idx, signer := range signers {
			err := signer.AddCollection(collectionID)
			require.NoError(t, err)

			err = signer.Store(publicKeyDoc)
			require.NoError(t, err)

			err = signer.Store(precomputationDocs[idx])
			require.NoError(t, err)
		}

		// Set threshold after all signers have been added.
		err = holder.SetThreshold(collectionID, threshold)
		require.NoError(t, err)

		// Generate credential Document
		credentialDoc, err := documentFromCredential([]byte(vcJSON), collectionID)
		require.NoError(t, err)
		require.NotNil(t, credentialDoc)

		// Set credential's index
		nextMsgIndex, err := thresholdbbsplusGenerator.NextMsgIndex() // Get next Index from Generator.
		require.NoError(t, err)
		err = holder.SetNextMsgIndex(collectionID, nextMsgIndex)
		require.NoError(t, err)
		signedCredentialDoc, err := holder.Sign(credentialDoc)
		require.NoError(t, err)
		require.NotNil(t, signedCredentialDoc)

		log.Println(string(signedCredentialDoc.Content))

		err = holder.Store(signedCredentialDoc)
		require.NoError(t, err)
		log.Println(signedCredentialDoc.ID)
		signedCredentialDoc2, err := holder.Get(Credential, signedCredentialDoc.ID, signedCredentialDoc.CollectionID)
		require.NoError(t, err)
		require.NotNil(t, signedCredentialDoc2)

		signedCredential, err := credentialFromDocument(signedCredentialDoc)
		require.NoError(t, err)
		require.NotNil(t, signedCredential.Proofs)

		// Holder verifies the signed credential.
		verificationResult, err := holder.Verify(signedCredentialDoc, publicKeyDoc)
		require.NoError(t, err)
		require.True(t, verificationResult)

		verificationResult2, err := holder.Verify(signedCredentialDoc2, publicKeyDoc)
		require.NoError(t, err)
		require.True(t, verificationResult2)
	})
}

func newMockProvider(t *testing.T) *mockprovider.Provider {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	serviceMap := map[string]interface{}{
		presentproofSvc.Name:    &mockpresentproof.MockPresentProofSvc{},
		outofbandSvc.Name:       &mockoutofband.MockOobService{},
		didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{},
		mediator.Coordination:   &mockmediator.MockMediatorSvc{},
		issuecredentialsvc.Name: &mockissuecredential.MockIssueCredentialSvc{},
		oobv2.Name:              &mockoutofbandv2.MockOobService{},
	}

	return &mockprovider.Provider{
		StorageProviderValue:              mockstorage.NewMockStoreProvider(),
		ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
		DocumentLoaderValue:               loader,
		ServiceMap:                        serviceMap,
	}
}
