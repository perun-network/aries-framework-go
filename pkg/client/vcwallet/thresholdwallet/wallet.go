package thresholdwallet

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	credential "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	StoreName = "RFC0593TransientStore"

	SigningDelay = 10 * time.Second // Default Delay for waiting partial signatures.
)

type Wallet interface {
	// Open opens makes the wallet's services available.
	Open() error

	// Close shutdowns the wallet's services.
	Close() error

	// DefaultHandler starts a handler, which automatically accepts all DIDComm Messages from DIDExchange and IssueCredential.
	DefaultHandler()

	// StartHandler starts a custom handler, which responses to incoming DIDComm Messages from the given channel.
	CustomHandler(channel chan service.DIDCommAction, credentialHandler func(events chan service.DIDCommAction)) error

	// ReplayProposal responses to a credential proposal with a corresponding offer.
	ReplayProposal(msg service.DIDCommMsg) (interface{}, *rfc0593.CredentialSpecOptions, error)

	// ReplayOffers responses to an issuecredential offer with a corresponding request.
	ReplayOffer(msg service.DIDCommMsg) (interface{}, *rfc0593.CredentialSpecOptions, error)

	// ReplayRequest responses to a request message by creates a issue credential message.
	ReplayRequest(msg service.DIDCommMsg) (interface{}, *rfc0593.CredentialSpecOptions, error)

	// ReplayCredential responses to an credential message.
	ReplayCredential(db storage.Store, msg service.DIDCommMsg) (interface{}, *rfc0593.CredentialSpecOptions, error)

	// Store adds a new document to wallet.
	Store(document *Document) error

	// AddCollection adds a new collection to wallet.
	AddCollection(collectionID string) error

	// Get retrieves a document from the wallet based on its content type and ID.
	Get(contentType ContentType, documentID string, collectionID string) (*Document, error)

	// GetCollection retrieves all documents from a collection based on the collectionID.
	GetCollection(collectionID string) ([]*Document, error)

	// Remove removes a document from the wallet based on its ID.
	Remove(contentType ContentType, documentID string) error

	// RemoveCollection removes an entire collection from the wallet.
	RemoveCollection(collectionID string) error

	// Sign signs the credential and produces a signed credential.
	Sign(credential *Document) (*Document, error)

	// Verify verifies the signature of the credential with the provided public key.
	Verify(signedCredential *Document, publicKey *Document) (bool, error)

	// Invite creates an invitation for DID connection.
	Invite(peerID string) (*didexchange.Invitation, error)

	// Connect create a connection with another client using a DIDComm invitation.
	Connect(*didexchange.Invitation) (string, error)

	// GetConnection gets a connection of the wallet through its inviation.
	GetConnection(invitationID string) (*didexchange.Connection, error)
}

// attachV1List creates a attachment for credential messages.
func attachV1List(vc *verifiable.Credential, created *time.Time, indices []int, nextMsgIndex int, collectionID string) ([]decorator.Attachment, error) {
	credSpec, err := createCredSpec(vc, created, indices, nextMsgIndex, collectionID)
	if err != nil {
		return nil, fmt.Errorf("create attachment: %w", err)
	}
	return []decorator.Attachment{
		{
			ID: "attach-1",
			Data: decorator.AttachmentData{
				JSON: credSpec,
			},
		},
	}, nil
}

// createCredSpec creates a Credential specification following RFC0593 convention.
func createCredSpec(vc *verifiable.Credential, created *time.Time, indices []int, nextMsgIndex int, collectionID string) (*rfc0593.CredentialSpec, error) {
	vcByte, err := vc.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal raw verifiable credential	: %s", err)
	}

	indicesBytes, err := json.Marshal(indices)
	if err != nil {
		return nil, err
	}

	return &rfc0593.CredentialSpec{
		Template: vcByte,
		Options: &rfc0593.CredentialSpecOptions{
			ProofPurpose: "assertionMethod",
			Created:      created.Format(time.RFC3339),
			Domain:       strconv.Itoa(nextMsgIndex),
			Challenge:    string(indicesBytes),
			Status: &rfc0593.CredentialStatus{
				Type: collectionID,
			},
			ProofType: bbsblssignature2020.SignatureType,
		},
	}, nil
}

// formatList creates a format for issue credential messages based on ld-proof-vc RFC.
func formatList() []credential.Format {
	return []credential.Format{
		{
			AttachID: "attach-1",
			Format:   "aries/ld-proof-vc-detail@v1.0",
		},
	}
}

// saveOptionsIfNoError saves message's data for processing.
func saveOptionsIfNoError(err error, s storage.Store, msg service.DIDCommMsg, options *rfc0593.CredentialSpecOptions) error {
	if err != nil {
		return err
	}

	thid, err := msg.ThreadID()
	if err != nil {
		return fmt.Errorf("failed to get message's threadID: %w", err)
	}

	raw, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	return s.Put(thid, raw)
}

// fetchCredentialSpecOptions gets the modification for Aries IssueCredential Protocol.
func fetchCredentialSpecOptions(s storage.Store, msg service.DIDCommMsg) (*rfc0593.CredentialSpecOptions, error) {
	thid, err := msg.ThreadID()
	if err != nil {
		return nil, fmt.Errorf("failed to get message's threadID: %w", err)
	}

	raw, err := s.Get(thid)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch options from store with threadID %s: %w", thid, err)
	}

	options := &rfc0593.CredentialSpecOptions{}

	return options, json.Unmarshal(raw, options)
}
