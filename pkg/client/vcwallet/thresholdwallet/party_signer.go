package thresholdwallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	jsonld "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/client/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	credential "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
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
	userID          string
	didexchange     *didexchange.Client
	issuecredential *issuecredential.Client
	vcwallet        *vcwallet.Client
	context         provider
	collectionIDs   []string
	signer          *signer.ThresholdBBSG2SignaturePartySigner
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
	didexchange, err := didexchange.New(ctx)
	if err != nil {
		return nil, err
	}

	issuecredential, err := issuecredential.New(ctx)
	if err != nil {
		return nil, err
	}
	vcwallet, err := vcwallet.New(userID, ctx, options...)
	if err != nil {
		return nil, err
	}
	return &PartySigner{
		userID:          userID,
		didexchange:     didexchange,
		issuecredential: issuecredential,
		vcwallet:        vcwallet,
		context:         ctx,
		collectionIDs:   make([]string, 0),
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

	err := c.handle()
	if err != nil {
		return err
	}
	return nil
}

// Handle runs the agent's handlers for didexchange and issue credential.
func (c *PartySigner) handle() error {
	err := c.handleDidExchange()
	if err != nil {
		return err
	}

	err = c.handleIssueCredential()
	if err != nil {
		return err
	}
	return nil
}

func (c *PartySigner) handleDidExchange() error {
	// Setup actions channels.
	actionsDidExchange := make(chan service.DIDCommAction)
	err := c.didexchange.RegisterActionEvent(actionsDidExchange)
	if err != nil {
		return fmt.Errorf("failed to register didexchange channel for %s: %w", c.userID, err)
	}
	go func() {
		service.AutoExecuteActionEvent(actionsDidExchange)
	}()
	return nil
}

func (c *PartySigner) handleIssueCredential() error {
	actionsIssueCredential := make(chan service.DIDCommAction)
	err := c.issuecredential.RegisterActionEvent(actionsIssueCredential)
	if err != nil {
		return fmt.Errorf("failed to register issuecredential channel for %s: %w", c.userID, err)
	}

	go func(events chan service.DIDCommAction) {
		db, storeErr := c.context.ProtocolStateStorageProvider().OpenStore(StoreName)
		for event := range events {
			if storeErr != nil {
				event.Stop(fmt.Errorf("rfc0593: failed to open transient store: %w", storeErr))
				continue
			}

			var (
				arg     interface{}
				options *rfc0593.CredentialSpecOptions
				err     error
			)

			switch event.Message.Type() {
			case credential.ProposeCredentialMsgTypeV2:
				arg, options, err = rfc0593.ReplayProposal(c.context, event.Message)
				err = saveOptionsIfNoError(err, db, event.Message, options)
			case credential.RequestCredentialMsgTypeV2:
				arg, options, err = c.issueCredential(event.Message)
				err = saveOptionsIfNoError(err, db, event.Message, options)
			default:
				event.Stop(fmt.Errorf("rfc0593: unsupported issue credential message type"))
				continue
			}

			if err != nil {
				event.Stop(err)
				continue
			}
			event.Continue(arg)
		}
	}(actionsIssueCredential)
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
	c.setSigner(credential.CollectionID)

	// Init bbs+ partial signature signer.
	c.signer.SetNexMsgIndex(credential.MsgIndex)
	c.signer.SetIndices(credential.Indices, credential.MsgIndex)
	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(c.signer),
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

// Invite creates an invitation for DID connection.
func (c *PartySigner) Invite(peerID string) (*didexchange.Invitation, error) {
	didInvitation, err := c.didexchange.CreateInvitation(fmt.Sprintf("%s want to connect with %s", c.userID, peerID))
	if err != nil {
		return nil, fmt.Errorf("create didexchange invitation: %w", err)
	}
	return didInvitation, nil
}

// Connect create a connection with another client using a DIDComm invitation.
func (c *PartySigner) Connect(invitation *didexchange.Invitation) (string, error) {
	connectionID, err := c.didexchange.HandleInvitation(invitation)
	if err != nil {
		return "", fmt.Errorf("connect didexchange invitation: %w", err)
	}
	return connectionID, nil
}

// GetConnection gets a connection of the wallet through its inviation.
func (c *PartySigner) GetConnection(invitation *didexchange.Invitation) (*didexchange.Connection, error) {
	connections, err := c.didexchange.QueryConnections(
		&didexchange.QueryConnectionsParams{
			InvitationID: invitation.ID,
		})
	if err != nil {
		return nil, err
	}

	if len(connections) != 1 {
		return nil, errors.New("client has wrong number of connections: != 1")
	}

	return connections[0], nil
}

func (c *PartySigner) issueCredential(msg service.DIDCommMsg) (interface{}, *rfc0593.CredentialSpecOptions, error) {
	request := &issuecredential.RequestCredentialV2{}

	err := msg.Decode(request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode msg type %s: %w", msg.Type(), err)
	}

	payload, err := rfc0593.GetCredentialSpec(c.context, request.Formats, request.RequestsAttach)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get payload for msg type %s: %w", msg.Type(), err)
	}

	ic, err := c.createIssueCredentialMsg(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create issue-credential msg: %w", err)
	}

	ic.Comment = fmt.Sprintf("response to request with id %s", msg.ID())

	return credential.WithIssueCredentialV2(ic), payload.Options, nil
}

func (c *PartySigner) createIssueCredentialMsg(spec *rfc0593.CredentialSpec) (*credential.IssueCredentialV2, error) {
	vc, err := verifiable.ParseCredential(
		spec.Template,
		verifiable.WithDisabledProofCheck(), // no proof is expected in this credential
		verifiable.WithJSONLDDocumentLoader(c.context.JSONLDDocumentLoader()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vc: %w", err)
	}

	ldProofContext, err := c.ldProofContext(spec)
	if err != nil {
		return nil, fmt.Errorf("create ld-proof context: %w", err)
	}

	err = vc.AddLinkedDataProof(ldProofContext, jsonld.WithDocumentLoader(c.context.JSONLDDocumentLoader()))
	if err != nil {
		return nil, fmt.Errorf("add partial signature to vc: %w", err)
	}

	attachID := uuid.New().String()

	return &credential.IssueCredentialV2{
		Type: credential.IssueCredentialMsgTypeV2,
		Formats: []credential.Format{{
			AttachID: attachID,
			Format:   rfc0593.ProofVCFormat,
		}},
		CredentialsAttach: []decorator.Attachment{{
			ID:       attachID,
			MimeType: "application/ld+json",
			Data: decorator.AttachmentData{
				JSON: vc,
			},
		}},
	}, nil
}

func (c *PartySigner) ldProofContext(spec *rfc0593.CredentialSpec) (*verifiable.LinkedDataProofContext, error) {
	var indices []int
	err := json.Unmarshal([]byte(spec.Options.Challenge), &indices)
	if err != nil {
		return nil, err
	}

	nextMsgIndex, err := strconv.Atoi(spec.Options.Domain)
	if err != nil {
		return nil, err
	}

	collectionID := spec.Options.Status.Type

	// Get precomputation with the same collectionID as the credential.
	c.setSigner(collectionID)

	// Init bbs+ partial signature signer.
	c.signer.SetNexMsgIndex(nextMsgIndex)
	c.signer.SetIndices(indices, nextMsgIndex)
	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(c.signer),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()))

	created, err := time.Parse(time.RFC3339, spec.Options.Created)
	if err != nil {
		return nil, err
	}

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      "did:bbspublickey#key",
		Created:                 &created,
	}

	return ldpContext, nil
}

func (c *PartySigner) setSigner(collectionID string) error {
	// Get precomputation with the same collectionID as the credential.
	collection, err := c.GetCollection(collectionID)
	if err != nil {
		return err
	}

	var precomputation *Document
	for _, document := range collection {
		if document.Type == Precomputation {
			precomputation = document
		}
	}
	if precomputation == nil {
		return errors.New("precomputation not found")
	}

	partySigner, err := signer.NewThresholdBBSG2SignaturePartySigner(precomputation.Content)
	if err != nil {
		return err
	}
	c.signer = partySigner
	return nil
}
