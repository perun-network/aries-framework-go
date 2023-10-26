package thresholdwallet

import (
	"encoding/json"
	"errors"
	"fmt"

	jsonld "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/client/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"golang.org/x/exp/slices"
)

// provider contains dependencies for the verifiable credential wallet client
// and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
	Crypto() crypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
	MediaTypeProfiles() []string
	didCommProvider // to be used only if wallet needs to be participated in DIDComm.
}

// didCommProvider to be used only if wallet needs to be participated in DIDComm operation.
// TODO: using wallet KMS instead of provider KMS.
// TODO: reconcile Protocol storage with wallet store.
type didCommProvider interface {
	KMS() kms.KeyManager
	ServiceEndpoint() string
	ProtocolStateStorageProvider() storage.Provider
	Service(id string) (interface{}, error)
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
}

// Party Signer are clients that produces partial signature for a credential using its precomputation.
type PartySigner struct {
	userID        string
	vcwallet      *vcwallet.Client
	context       provider
	collectionIDs []string
}

// NewPartySigner returns new party signer client with verifiable credential wallet for given user.
//
//	Args:
//		- userID : unique user identifier used for login.
//		- provider: dependencies for the verifiable credential wallet client.
//		- options : options for unlocking wallet. Any other existing wallet instance of same wallet user will be locked
//		once this instance is unlocked.
//
// returns error if wallet profile is not found.
// To create a new wallet profile, use `CreateProfile()`.
// To update an existing profile, use `UpdateProfile()`.
func NewPartySigner(userID string, ctx provider, options ...wallet.UnlockOptions) (*PartySigner, error) {
	vcwallet, err := vcwallet.New(userID, ctx, options...)
	if err != nil {
		return nil, err
	}
	return &PartySigner{
		userID:        userID,
		vcwallet:      vcwallet,
		context:       ctx,
		collectionIDs: make([]string, 0),
	}, nil
}

// CreateProfile creates a new verifiable credential wallet profile for given user.
// returns error if wallet profile is already created.
// Use `UpdateProfile()` for replacing an already created verifiable credential wallet profile.
func CreateProfile(userID string, ctx provider, options ...wallet.ProfileOptions) error {
	return wallet.CreateProfile(userID, ctx, options...)
}

// UpdateProfile updates existing verifiable credential wallet profile.
// Will create new profile if no profile exists for given user.
// Caution: you might lose your existing keys if you change kms options.
func UpdateProfile(userID string, ctx provider, options ...wallet.ProfileOptions) error {
	return wallet.UpdateProfile(userID, ctx, options...)
}

// ProfileExists checks if profile exists for given wallet user, returns error if not found.
func ProfileExists(userID string, ctx provider) error {
	return wallet.ProfileExists(userID, ctx)
}

// Open unlocks wallet client's key manager instance and returns a token for subsequent use of wallet features.
//
//	Args:
//		- unlock options for opening wallet.
//
//	Returns error if unlock fails.
func (c *PartySigner) Open(options ...wallet.UnlockOptions) error {
	if err := c.vcwallet.Open(options...); err != nil {
		return err
	}
	return nil
}

// Close expires token issued to this VC wallet client.
// returns false if token is not found or already expired for this wallet user.
func (c *PartySigner) Close() error {
	result := c.vcwallet.Close()
	if result {
		return nil
	}
	return errors.New("close failed")
}

// Store adds the given document to wallet contents store.
//
// Supported document type:
//   - Credential
//   - Precomputation
//   - PublicKey
//
// Returns error if failed.
func (c *PartySigner) Store(document *Document) error {
	// Check if the document's collection is already stored.
	if !slices.Contains(c.collectionIDs, document.CollectionID) {
		collection := newCollection(document.CollectionID, c.userID)
		collectionBytes, err := json.Marshal(collection)
		if err != nil {
			return fmt.Errorf("marshal collection: %w", err)
		}
		err = c.vcwallet.Add(wallet.Collection, collectionBytes)
		if err != nil {
			return fmt.Errorf("add a new collection to wallet: %w", err)
		}
		c.collectionIDs = append(c.collectionIDs, collection.ID)
	}

	// Store document based on its type.
	switch document.Type {
	case Credential:
		cred, err := credentialFromDocument(document)
		if err != nil {
			return fmt.Errorf("create credential: %w", err)
		}
		credBytes, err := cred.MarshalJSON()
		if err != nil {
			return fmt.Errorf("marshal credential: %w", err)
		}
		err = c.vcwallet.Add(wallet.Credential,
			credBytes,
			wallet.AddByCollection(document.CollectionID))
		if err != nil {
			return fmt.Errorf("add new credential to wallet: %w", err)
		}
	case Precomputation, PublicKey:
		metadata, err := newMetadata(document)
		if err != nil {
			return fmt.Errorf("create signature: %w", err)
		}
		metadataBytes, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("marshal signature: %w", err)
		}
		err = c.vcwallet.Add(wallet.Metadata,
			metadataBytes,
			wallet.AddByCollection(document.CollectionID))
		if err != nil {
			return fmt.Errorf("add metadata to collection: %w", err)
		}
	default:
		return errors.New("unknown document type")
	}
	return nil
}

// AddCollection adds a new collection to group documents given its collectionID.
// Returns error if the collection already existed.
func (c *PartySigner) AddCollection(collectionID string) error {
	collection := newCollection(collectionID, c.userID)
	collectionBytes, err := json.Marshal(collection)
	if err != nil {
		return fmt.Errorf("marshal collection: %w", err)
	}
	err = c.vcwallet.Add(wallet.Collection, collectionBytes)
	if err != nil {
		return fmt.Errorf("add a new collection to wallet: %w", err)
	}
	c.collectionIDs = append(c.collectionIDs, collection.ID)
	return nil
}

// Get retrieves the document from the wallet contents store. based on its ID and content Type.
//
// Supported document type:
//   - Credential
//   - Precomputation
//   - PublicKey
//
// Returns error if the document is not found.
func (c *PartySigner) Get(contentType ContentType, documentID string, collectionID string) (*Document, error) {
	switch contentType {
	case Credential:
		credentialsBytes, err := c.vcwallet.GetAll(wallet.Credential, wallet.FilterByCollection(collectionID))
		if err != nil {
			return nil, err
		}
		document, err := documentFromCredential(credentialsBytes[documentID], collectionID)
		if err != nil {
			return nil, fmt.Errorf("retrieve document from credential: %w", err)
		}
		return document, nil
	case Precomputation, PublicKey:
		metadatasBytes, err := c.vcwallet.GetAll(wallet.Metadata, wallet.FilterByCollection(collectionID))
		if err != nil {
			return nil, err
		}
		var metadata ThresholdWalletMetaData
		err = json.Unmarshal(metadatasBytes[documentID], &metadata)
		if err != nil {
			return nil, fmt.Errorf("unmarshal metadata  bytes: %w", err)
		}
		document := metadata.Subject
		if document.Type == contentType {
			return document, nil
		}
		return nil, errors.New("document has wrong type")

	default:
		return nil, errors.New("unsupported document type")
	}
}

// GetCollection retrieves all the documents from a collection.
// Returns error if collection did not exist or retrieve documents failed.
func (c *PartySigner) GetCollection(collectionID string) ([]*Document, error) {
	var collection []*Document

	// Get all credentials from the collection.
	credentials, err := c.vcwallet.GetAll(wallet.Credential, wallet.FilterByCollection(collectionID))
	if err != nil {
		return nil, fmt.Errorf("get credentials with collection id %s: %w", collectionID, err)
	}
	for _, value := range credentials {
		document, err := documentFromCredential(value, collectionID)
		if err != nil {
			return nil, fmt.Errorf("retrieve document from credential: %w", err)
		}
		collection = append(collection, document)
	}

	// Get all metadatas from the collection
	metadatas, err := c.vcwallet.GetAll(wallet.Metadata, wallet.FilterByCollection(collectionID))
	if err != nil {
		return nil, fmt.Errorf("get signatures with collection id %s: %w", collectionID, err)
	}
	for key, value := range metadatas {
		var metadata ThresholdWalletMetaData
		err := json.Unmarshal(value, &metadata)
		if err != nil {
			return nil, fmt.Errorf("unmarshal metadata %s: %w", key, err)
		}

		document := metadata.Subject
		collection = append(collection, document)
	}
	return collection, nil
}

// Remove deletes the document from wallet contents store given its type and ID.
//
// Supported document type:
//   - Credential
//   - Precomputation
//   - PublicKey
//
// Returns error if remove failed.
func (c *PartySigner) Remove(contentType ContentType, documentID string) error {
	switch contentType {
	case Credential:
		err := c.vcwallet.Remove(wallet.Credential, documentID)
		if err != nil {
			return err
		}
		return nil
	case Precomputation, PublicKey:
		err := c.vcwallet.Remove(wallet.Metadata, documentID)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("remove content type not supported")
	}
}

// RemoveCollection removes a collection with all of its documents given collectionID.
// Returns error if remove failed.
func (c *PartySigner) RemoveCollection(collectionID string) error {
	documents, err := c.GetCollection(collectionID)
	if err != nil {
		return err
	}
	for _, document := range documents {
		err := c.Remove(document.Type, document.ID)
		if err != nil {
			return err
		}
	}

	err = c.vcwallet.Remove(wallet.Collection, collectionID)
	if err != nil {
		return fmt.Errorf("remove collection from wallet: %w", err)
	}

	for i, v := range c.collectionIDs {
		if v == collectionID {
			// Remove the element by creating a new slice without it
			c.collectionIDs = append(c.collectionIDs[:i], c.collectionIDs[i+1:]...)
			break
		}
	}
	return nil
}

// Sign adds partial signature proof to a Verifiable Credential.
// The party signer must first retrieve presignature from its precomputation,
// with the same collectionID as the credential.
//
// Returns error if Sign failed.
func (c *PartySigner) Sign(credential *Document) (*Document, error) {
	vc, err := verifiable.ParseCredential(credential.Content,
		verifiable.WithJSONLDDocumentLoader(c.context.JSONLDDocumentLoader()),
		verifiable.WithCredDisableValidation(),
	)
	if err != nil {
		return nil, err
	}

	// Get precomputation with the same collectionID as the credential.
	collection, err := c.GetCollection(credential.CollectionID)
	if err != nil {
		return nil, err
	}

	var precomputation *Document
	for _, document := range collection {
		if document.Type == Precomputation {
			precomputation = document
		}
	}
	if precomputation == nil {
		return nil, errors.New("precomputation not found")
	}

	partySigner, err := signer.NewThresholdBBSG2SignaturePartySigner(precomputation.Content)
	if err != nil {
		return nil, err
	}

	// Init bbs+ partial signature signer.
	partySigner.SetNexMsgIndex(credential.MsgIndex)
	partySigner.SetIndices(credential.Indices, credential.MsgIndex)
	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(partySigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      "did:bbspublickey#key",
		Created:                 credential.Created,
	}

	err = vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(c.context.JSONLDDocumentLoader()))
	if err != nil {
		return nil, err
	}

	vcSignedBytes, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}
	signedCredential := NewDocument(Credential, vcSignedBytes, credential.CollectionID)
	signedCredential.Indices = credential.Indices
	signedCredential.MsgIndex = credential.MsgIndex
	return signedCredential, nil
}

// Verify checked the signed credential and used the given public key to verify its signature.
// Supported:
// - Bls12381G2Key2020
//
// Returns true if verification succeed and false if verification failed.
// Returns error if parse credential failed.
func (c *PartySigner) Verify(signedCredential *Document, publicKey *Document) (bool, error) {
	_, err := verifiable.ParseCredential(signedCredential.Content,
		verifiable.WithJSONLDDocumentLoader(c.context.JSONLDDocumentLoader()),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(publicKey.Content, "Bls12381G2Key2020")))
	if err != nil {
		return false, fmt.Errorf("credential verification failed: %w", err)
	}
	return true, nil
}
