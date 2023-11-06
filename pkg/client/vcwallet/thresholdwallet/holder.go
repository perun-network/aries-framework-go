package thresholdwallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/google/uuid"
	jsonld "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	ldproof "github.com/hyperledger/aries-framework-go/component/models/ld/proof"
	"github.com/hyperledger/aries-framework-go/component/models/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/client/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	credential "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"golang.org/x/exp/slices"
)

// Holders is a Wallet Client that want a credential to be signed
// and request the signing with all party signers.
type Holder struct {
	userID            string
	didexchange       *didexchange.Client
	issuecredential   *issuecredential.Client
	vcwallet          *vcwallet.Client
	context           provider
	collectionIDs     []string
	threshold         map[string]int // Theshold must be set based on precomputations generation.
	msgIndex          map[string]int // msgIndex must be obtained from the precomputation generator.
	partySigners      map[string][]*didexchange.Connection
	partialSignatures map[string][][]byte
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
	didexchangeSvc, err := didexchange.New(ctx)
	if err != nil {
		return nil, err
	}

	issuecredentialSvc, err := issuecredential.New(ctx)
	if err != nil {
		return nil, err
	}

	vcwallet, err := vcwallet.New(userID, ctx, options...)
	if err != nil {
		return nil, err
	}
	holder := &Holder{
		userID:            userID,
		vcwallet:          vcwallet,
		didexchange:       didexchangeSvc,
		issuecredential:   issuecredentialSvc,
		context:           ctx,
		collectionIDs:     make([]string, 0),
		threshold:         make(map[string]int),
		msgIndex:          make(map[string]int),
		partySigners:      make(map[string][]*didexchange.Connection),
		partialSignatures: make(map[string][][]byte),
	}
	err = holder.handle()
	if err != nil {
		return nil, err
	}
	return holder, nil
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
	err := c.handle()
	if err != nil {
		return err
	}
	return nil
}

// Handle runs the agent's handlers for didexchange and issue credential.
func (c *Holder) handle() error {
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

func (c *Holder) handleDidExchange() error {
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

func (c *Holder) handleIssueCredential() error {
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
			messType := event.Message.Type()
			switch messType {
			case credential.OfferCredentialMsgTypeV2:
				log.Println("Received offer")
				arg, options, err = c.replayOffer(event.Message)
				err = saveOptionsIfNoError(err, db, event.Message, options)
			case credential.IssueCredentialMsgTypeV2:
				log.Println("Received credential")
				options, err = fetchCredentialSpecOptions(db, event.Message)
				if err != nil {
					err = fmt.Errorf("failed to fetch credential spec options to validate credential: %w", err)
					break
				}

				var partialSignature []byte
				arg, partialSignature, err = fetchPartialCredential(c.context, uuid.New().String(), event.Message)
				if err == nil {
					collectionID := options.Status.Type
					c.partialSignatures[collectionID] = append(c.partialSignatures[collectionID], partialSignature)
				}
			default:
				event.Stop(fmt.Errorf("rfc0593: unsupported issue credential messages"))
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
	created := time.Now()                                                                                                // Time of issuance, sync for all party signers.
	indices := generateRandomIndices(c.threshold[credential.CollectionID], len(c.partySigners[credential.CollectionID])) // Choose random signers.
	// Obtains partial signatures.
	c.partialSignatures[credential.CollectionID] = make([][]byte, 0)

	for i := 0; i < c.threshold[credential.CollectionID]; i++ {
		// Create a channel to signal that the timeout has occurred
		partialCredential := NewDocument(Credential, credential.Content, credential.CollectionID)
		partialCredential.Indices = indices                              // Set indices for party signer.
		partialCredential.MsgIndex = c.msgIndex[credential.CollectionID] // Set message Index for party signer.
		partialCredential.Created = &created                             // Set issuance time.

		c.ProposeCredential(c.partySigners[credential.CollectionID][indices[i]-1], partialCredential)
		log.Printf("Holder proposed credential to signer %d", indices[i]-1)
		/*
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
		*/
	}
	time.Sleep(signingDelay)
	// Create Threshold BBS+ Signature Suite.
	thresholdSigner := signer.NewThresholdBBSG2SignatureSigner(c.threshold[credential.CollectionID], credential.MsgIndex, c.partialSignatures[credential.CollectionID])
	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(thresholdSigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()))

	createdFormated, err := time.Parse(time.RFC3339, created.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      "did:bbspublickey#key",
		Created:                 &createdFormated,
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

// Invite creates an invitation for DID connection.
func (c *Holder) Invite(peerID string) (*didexchange.Invitation, error) {
	didInvitation, err := c.didexchange.CreateInvitation(fmt.Sprintf("%s want to connect with %s", c.userID, peerID))
	if err != nil {
		return nil, fmt.Errorf("create didexchange invitation: %w", err)
	}
	return didInvitation, nil
}

// Connect create a connection with another client using a DIDComm invitation.
func (c *Holder) Connect(invitation *didexchange.Invitation) (string, error) {
	connectionID, err := c.didexchange.HandleInvitation(invitation)
	if err != nil {
		return "", fmt.Errorf("connect didexchange invitation: %w", err)
	}
	time.Sleep(5 * time.Second)
	return connectionID, nil
}

// GetConnection gets a connection of the wallet through its inviation.
func (c *Holder) GetConnection(invitationID string) (*didexchange.Connection, error) {
	connections, err := c.didexchange.QueryConnections(
		&didexchange.QueryConnectionsParams{
			InvitationID: invitationID,
		})
	if err != nil {
		return nil, err
	}

	if len(connections) != 1 {
		return nil, errors.New("client has wrong number of connections: != 1")
	}

	return connections[0], nil
}

// AddPartySigner adds a new party signer to be used in signing credentials.
// Returns error on nil-pointer.
func (c *Holder) AddPartySigner(collectionID string, connection *didexchange.Connection) error {
	if connection == nil {
		return errors.New("nil pointer party signer")
	}
	if c.partySigners[collectionID] == nil {
		c.partySigners[collectionID] = make([]*didexchange.Connection, 0)
	}
	c.partySigners[collectionID] = append(c.partySigners[collectionID], connection)
	return nil
}

// RemovePartySigner removes a party signer from signing future partial signatures.
// Returns error if the given ID was not found.
func (c *Holder) RemovePartySigner(collectionID string, connectionID string) error {
	if c.partySigners[collectionID] == nil {
		return fmt.Errorf("collection with ID %s not found", collectionID)
	}

	var newPartySigners []*didexchange.Connection

	for _, party := range c.partySigners[collectionID] {
		if connectionID != party.ConnectionID {
			newPartySigners = append(newPartySigners, party)
		}
	}

	if len(newPartySigners) == len(c.partySigners) {
		return fmt.Errorf("party wallet with connection ID %s not found", connectionID)
	}

	c.partySigners[collectionID] = newPartySigners
	return nil
}

// ProposeCredential proposes partial signature from a signer through its connection.
func (c *Holder) ProposeCredential(connection *didexchange.Connection, credDoc *Document) error {
	vc, err := credentialFromDocument(credDoc)
	if err != nil {
		return err
	}

	filtersAttach, err := attachV1List(vc,
		credDoc.Created,
		credDoc.Indices,
		credDoc.MsgIndex,
		credDoc.CollectionID)
	if err != nil {
		return err
	}

	src := credential.ProposeCredentialV2{
		Type:          credential.ProposeCredentialMsgTypeV2,
		Comment:       "Request partial signature",
		Formats:       formatList(),
		FiltersAttach: filtersAttach,
	}

	srcBytes, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("create propose credential: failed to marshal raw offer: %w", err)
	}

	proposal := credential.ProposeCredentialParams{}

	err = json.Unmarshal(srcBytes, &proposal)
	if err != nil {
		return fmt.Errorf("create propose credential: failed to unmarshal full offer: %w", err)
	}

	_, err = c.issuecredential.SendProposal(&proposal, connection.Record)
	if err != nil {
		return fmt.Errorf("failed to send proposal: %w", err)
	}

	return nil
}

// SetThreshold sets the threshold for signing next verifiable credential.
func (c *Holder) SetThreshold(collectionID string, threshold int) error {
	if !slices.Contains(c.collectionIDs, collectionID) {
		return errors.New("collectionID not found")
	}

	if len(c.partySigners[collectionID]) < threshold {
		return errors.New("threshold out of bound")
	}
	c.threshold[collectionID] = threshold
	return nil
}

// SetNextMsgIndex sets the index for signing next verifiable credential.
func (c *Holder) SetNextMsgIndex(collectionID string, nextMsgIndex int) error {
	if !slices.Contains(c.collectionIDs, collectionID) {
		return errors.New("collectionID not found")
	}

	c.msgIndex[collectionID] = nextMsgIndex
	return nil
}

// generateRandomIndices create a random set of unique, unduplicated indices.
// Returns an array of indices with size threshold and value range from 1 to numOfParties.
func generateRandomIndices(threshold, numOfParties int) []int {
	if numOfParties < threshold {
		panic("threshold must be <= num of parties")
	}
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

// fetchCredentialSpecOptions gets the modification for Aries IssueCredential Protocol.
func fetchPartialCredential(p provider, name string, msg service.DIDCommMsg) (interface{}, []byte, error) {
	issueCredential := &issuecredential.IssueCredentialV2{}
	err := msg.Decode(issueCredential)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode msg type %s: %w", msg.Type(), err)
	}

	attachment, err := rfc0593.FindAttachment(rfc0593.ProofVCFormat, issueCredential.Formats, issueCredential.CredentialsAttach)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch attachment with format %s: %w", rfc0593.ProofVCFormat, err)
	}

	raw, err := attachment.Data.Fetch()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch the attachment's contents: %w", err)
	}

	vc, err := verifiable.ParseCredential(
		raw,
		verifiable.WithJSONLDDocumentLoader(p.JSONLDDocumentLoader()),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithCredDisableValidation(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse partial signed credential: %w", err)
	}

	partialSignature, err := validatePartialSignature(vc.Proofs[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate partial signature: %w", err)
	}

	return credential.WithFriendlyNames(name), partialSignature, nil
}

func (c *Holder) replayOffer(msg service.DIDCommMsg) (interface{}, *rfc0593.CredentialSpecOptions, error) {
	offer := &credential.OfferCredentialV2{}

	err := msg.Decode(offer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode msg type %s: %w", msg.Type(), err)
	}

	payload, err := c.getCredentialSpec(offer.Formats, offer.OffersAttach)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract payoad for msg type %s: %w", msg.Type(), err)
	}

	attachID := uuid.New().String()

	return credential.WithRequestCredentialV2(&credential.RequestCredentialV2{
		Type:    credential.RequestCredentialMsgTypeV2,
		Comment: fmt.Sprintf("response to msg id: %s", msg.ID()),
		Formats: []credential.Format{{
			AttachID: attachID,
			Format:   rfc0593.ProofVCDetailFormat,
		}},
		RequestsAttach: []decorator.Attachment{{
			ID:       attachID,
			MimeType: "application/json",
			Data: decorator.AttachmentData{
				JSON: payload,
			},
		}},
	}), payload.Options, nil
}

// GetCredentialSpec extracts the CredentialSpec from the formats and attachments.
func (c *Holder) getCredentialSpec(
	formats []credential.Format, attachments []decorator.Attachment) (*rfc0593.CredentialSpec, error) {
	attachment, err := rfc0593.FindAttachment(rfc0593.ProofVCDetailFormat, formats, attachments)
	if err != nil {
		return nil, fmt.Errorf("failed to find attachment of type %s: %w", rfc0593.ProofVCDetailFormat, err)
	}

	payload := &rfc0593.CredentialSpec{}

	err = unmarshalAttachmentContents(attachment, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attachment contents: %w", err)
	}

	_, err = verifiable.ParseCredential(
		payload.Template,
		verifiable.WithCredDisableValidation(),
		verifiable.WithDisabledProofCheck(), // no proof is expected in this credential
		verifiable.WithJSONLDDocumentLoader(c.context.JSONLDDocumentLoader()),
	)
	if err != nil {
		return nil, fmt.Errorf("bad request: unable to parse vc: %w", err)
	}

	return payload, nil
}
