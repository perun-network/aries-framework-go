package thresholdwallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

	jsonld "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	ldproof "github.com/hyperledger/aries-framework-go/component/models/ld/proof"
	"github.com/hyperledger/aries-framework-go/component/models/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/client/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"golang.org/x/exp/slices"
)

// Holders is a Wallet Client that want a credential to be signed
// and request the signing with all party signers.
type Holder struct {
	userID        string
	vcwallet      *vcwallet.Client
	context       provider
	collectionIDs []string
	threshold     int // Theshold must be set based on precomputations generation.
	msgIndex      int // msgIndex must be obtained from the precomputation generator.
	partySigners  []*PartySigner
}

// NewHolder returns new holder client with verifiable credential wallet for given user.
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
func NewHolder(userID string, ctx provider, options ...wallet.UnlockOptions) (*Holder, error) {
	vcwallet, err := vcwallet.New(userID, ctx, options...)
	if err != nil {
		return nil, err
	}
	return &Holder{
		userID:        userID,
		vcwallet:      vcwallet,
		context:       ctx,
		collectionIDs: make([]string, 0),
		threshold:     -1,
		msgIndex:      0,
		partySigners:  make([]*PartySigner, 0),
	}, nil
}

// Open unlocks wallet client's key manager instance and returns a token for subsequent use of wallet features.
//
//	Args:
//		- unlock options for opening wallet.
//
//	Returns error if unlock fails.
func (c *Holder) Open(options ...wallet.UnlockOptions) error {
	if err := c.vcwallet.Open(options...); err != nil {
		return err
	}
	return nil
}

// Close expires token issued to this VC wallet client.
// returns error if token is not found or already expired for this wallet user.
func (c *Holder) Close() error {
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
func (c *Holder) Store(document *Document) error {
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
func (c *Holder) AddCollection(collectionID string) error {
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
func (c *Holder) Get(contentType ContentType, documentID string, collectionID string) (*Document, error) {
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
func (c *Holder) GetCollection(collectionID string) ([]*Document, error) {
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
func (c *Holder) Remove(contentType ContentType, documentID string) error {
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
func (c *Holder) RemoveCollection(collectionID string) error {
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

// Sign adds proof to a Verifiable Credential.
// The holder must first retrieve partial proofs from its party signers,
// and combine the partial proofs to obtained true proof.
//
// Returns error if Sign failed.
func (c *Holder) Sign(credential *Document) (*Document, error) {
	// Get verifiable credential.
	vc, err := verifiable.ParseCredential(credential.Content,
		verifiable.WithJSONLDDocumentLoader(c.context.JSONLDDocumentLoader()),
		verifiable.WithCredDisableValidation(),
	)
	if err != nil {
		return nil, err
	}
	created := time.Now()                                              // Time of issuance, sync for all party signers.
	indices := generateRandomIndices(c.threshold, len(c.partySigners)) // Choose random signers.
	// Obtains partial signatures.
	partialSignatures := make([][]byte, c.threshold)
	for i := 0; i < c.threshold; i++ {
		partialCredential := NewDocument(Credential, credential.Content, credential.CollectionID)
		partialCredential.Indices = indices     // Set indices for party signer.
		partialCredential.MsgIndex = c.msgIndex // Set message Index for party signer.
		partialCredential.Created = &created    // Set issuance time.
		partialSignedCredential, err := c.partySigners[indices[i]-1].Sign(partialCredential)
		if err != nil {
			return nil, err
		}

		// Get the partial signed verifiable credential.
		partialSignedVC, err := verifiable.ParseCredential(partialSignedCredential.Content,
			verifiable.WithJSONLDDocumentLoader(c.context.JSONLDDocumentLoader()),
			verifiable.WithCredDisableValidation(),
			verifiable.WithDisabledProofCheck(),
		)
		if err != nil {
			return nil, err
		}

		// Get the partial signature from the partial signed verifiable credential.
		partialSignature, err := validatePartialSignature(partialSignedVC.Proofs[0])
		if err != nil {
			return nil, err
		}

		partialSignatures[i] = partialSignature
	}

	// Create Threshold BBS+ Signature Suite.
	thresholdSigner := signer.NewThresholdBBSG2SignatureSigner(c.threshold, credential.MsgIndex, partialSignatures)
	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(thresholdSigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      "did:bbspublickey#key",
		Created:                 &created,
	}

	err = vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(c.context.JSONLDDocumentLoader()))
	if err != nil {
		return nil, err
	}

	vcSignedBytes, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}
	credential.Content = vcSignedBytes
	return credential, nil
}

// Verify checked the signed credential and used the given public key to verify its signature.
// Supported:
// - Bls12381G2Key2020
//
// Returns true if verification succeed and false if verification failed.
// Returns error if parse credential failed.
func (c *Holder) Verify(signedCredential *Document, publicKey *Document) (bool, error) {
	_, err := verifiable.ParseCredential(signedCredential.Content,
		verifiable.WithJSONLDDocumentLoader(c.context.JSONLDDocumentLoader()),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(publicKey.Content, "Bls12381G2Key2020")))
	if err != nil {
		return false, fmt.Errorf("credential verification failed: %w", err)
	}
	return true, nil
}

// AddPartySigner adds a new party signer to be used in signing credentials.
// Returns error on nil-pointer.
func (c *Holder) AddPartySigner(ps *PartySigner) error {
	if ps == nil {
		return errors.New("nil pointer party signer")
	}
	if c.partySigners == nil {
		c.partySigners = make([]*PartySigner, 0)
	}
	c.partySigners = append(c.partySigners, ps)
	return nil
}

// RemovePartySigner removes a party signer from signing future partial signatures.
// Returns error if the given ID was not found.
func (c *Holder) RemovePartySigner(psID string) error {
	var newPartySigners []*PartySigner

	for _, party := range c.partySigners {
		if party.userID != psID {
			newPartySigners = append(newPartySigners, party)
		}
	}

	if len(newPartySigners) == len(c.partySigners) {
		return fmt.Errorf("party wallet with ID %s not found", psID)
	}

	c.partySigners = newPartySigners
	return nil
}

// SetThreshold sets the threshold for signing next verifiable credential.
func (c *Holder) SetThreshold(threshold int) error {
	if len(c.partySigners) < threshold {
		return errors.New("threshold out of bound")
	}
	c.threshold = threshold
	return nil
}

// SetNextMsgIndex sets the index for signing next verifiable credential.
func (c *Holder) SetNextMsgIndex(nextMsgIndex int) error {
	c.msgIndex = nextMsgIndex
	return nil
}

// generateRandomIndices create a random set of unique, unduplicated indices.
// Returns an array of indices with size threshold and value range from 1 to numOfParties.
func generateRandomIndices(threshold, numOfParties int) []int {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	used := make(map[int]bool)

	indices := make([]int, 0)
	for len(indices) < threshold {
		r := rng.Intn(numOfParties) + 1
		if !used[r] {
			used[r] = true
			indices = append(indices, r)
		}
	}
	return indices
}

// validatePartialSignature checks the verifiable proof,
// and returns the actual partial signature if the format is correct.
func validatePartialSignature(proof verifiable.Proof) ([]byte, error) {

	sigType, ok := proof["type"].(string)
	if !ok {
		return nil, errors.New("missing type")
	}
	if sigType != "BbsBlsSignature2020" {
		return nil, errors.New("false signature type")
	}

	verificationMethod, ok := proof["verificationMethod"].(string)
	if !ok {
		return nil, errors.New("missing verfication method")
	}
	if verificationMethod != "did:bbspublickey#key" {
		return nil, errors.New("false verification method")
	}

	proofValue, ok := proof["proofValue"].(string)
	if !ok {
		return nil, errors.New("missing proofValue")
	}

	partialSignatureBytes, err := ldproof.DecodeProofValue(proofValue, "BbsBlsSignature2020")
	if err != nil {
		return nil, err
	}
	return partialSignatureBytes, nil
}
