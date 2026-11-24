package crosscheck

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
	"strconv"
)

// The request and response types follow the interop client interface; their
// JSON names are the protocol buffer field names and bytes are base64.

// jsonU64 reads a 64-bit integer sent as a JSON string or number.
type jsonU64 uint64

// UnmarshalJSON accepts "5" and 5.
func (u *jsonU64) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' {
		s = s[1 : len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	*u = jsonU64(v)
	return err
}

type empty struct{}

type stateRequest struct {
	StateID uint32 `json:"state_id"`
}

type createGroupRequest struct {
	GroupID          []byte `json:"group_id"`
	CipherSuite      uint32 `json:"cipher_suite"`
	EncryptHandshake bool   `json:"encrypt_handshake"`
	Identity         []byte `json:"identity"`
}

type createGroupResponse struct {
	StateID uint32 `json:"state_id"`
}

type createKeyPackageRequest struct {
	CipherSuite uint32 `json:"cipher_suite"`
	Identity    []byte `json:"identity"`
}

type createKeyPackageResponse struct {
	TransactionID  uint32 `json:"transaction_id"`
	KeyPackage     []byte `json:"key_package"`
	InitPriv       []byte `json:"init_priv"`
	EncryptionPriv []byte `json:"encryption_priv"`
	SignaturePriv  []byte `json:"signature_priv"`
}

type joinGroupRequest struct {
	TransactionID    uint32 `json:"transaction_id"`
	Welcome          []byte `json:"welcome"`
	EncryptHandshake bool   `json:"encrypt_handshake"`
	Identity         []byte `json:"identity"`
	RatchetTree      []byte `json:"ratchet_tree"`
}

type joinGroupResponse struct {
	StateID            uint32 `json:"state_id"`
	EpochAuthenticator []byte `json:"epoch_authenticator"`
}

type stateAuthResponse struct {
	StateAuthSecret []byte `json:"state_auth_secret"`
}

type exportRequest struct {
	StateID   uint32 `json:"state_id"`
	Label     string `json:"label"`
	Context   []byte `json:"context"`
	KeyLength uint32 `json:"key_length"`
}

type exportResponse struct {
	ExportedSecret []byte `json:"exported_secret"`
}

type protectRequest struct {
	StateID           uint32 `json:"state_id"`
	AuthenticatedData []byte `json:"authenticated_data"`
	Plaintext         []byte `json:"plaintext"`
}

type protectResponse struct {
	Ciphertext []byte `json:"ciphertext"`
}

type unprotectRequest struct {
	StateID    uint32 `json:"state_id"`
	Ciphertext []byte `json:"ciphertext"`
}

type unprotectResponse struct {
	AuthenticatedData []byte `json:"authenticated_data"`
	Plaintext         []byte `json:"plaintext"`
}

type storePSKRequest struct {
	StateOrTransactionID uint32 `json:"state_or_transaction_id"`
	PSKID                []byte `json:"psk_id"`
	PSKSecret            []byte `json:"psk_secret"`
}

type addProposalRequest struct {
	StateID    uint32 `json:"state_id"`
	KeyPackage []byte `json:"key_package"`
}

type removeProposalRequest struct {
	StateID   uint32 `json:"state_id"`
	RemovedID []byte `json:"removed_id"`
}

type externalPSKProposalRequest struct {
	StateID uint32 `json:"state_id"`
	PSKID   []byte `json:"psk_id"`
}

type resumptionPSKProposalRequest struct {
	StateID uint32  `json:"state_id"`
	EpochID jsonU64 `json:"epoch_id"`
}

type extension struct {
	ExtensionType uint32 `json:"extension_type"`
	ExtensionData []byte `json:"extension_data"`
}

type groupContextExtensionsProposalRequest struct {
	StateID    uint32      `json:"state_id"`
	Extensions []extension `json:"extensions"`
}

type proposalResponse struct {
	Proposal []byte `json:"proposal"`
}

type proposalDescription struct {
	ProposalType []byte      `json:"proposal_type"`
	KeyPackage   []byte      `json:"key_package"`
	RemovedID    []byte      `json:"removed_id"`
	PSKID        []byte      `json:"psk_id"`
	EpochID      jsonU64     `json:"epoch_id"`
	Extensions   []extension `json:"extensions"`
}

type commitRequest struct {
	StateID      uint32                `json:"state_id"`
	ByReference  [][]byte              `json:"by_reference"`
	ByValue      []proposalDescription `json:"by_value"`
	ForcePath    bool                  `json:"force_path"`
	ExternalTree bool                  `json:"external_tree"`
}

type commitResponse struct {
	Commit      []byte `json:"commit"`
	Welcome     []byte `json:"welcome,omitempty"`
	RatchetTree []byte `json:"ratchet_tree,omitempty"`
}

type handleCommitRequest struct {
	StateID  uint32   `json:"state_id"`
	Proposal [][]byte `json:"proposal"`
	Commit   []byte   `json:"commit"`
}

type handleCommitResponse struct {
	StateID            uint32 `json:"state_id"`
	EpochAuthenticator []byte `json:"epoch_authenticator"`
}

type createBranchRequest struct {
	StateID      uint32      `json:"state_id"`
	GroupID      []byte      `json:"group_id"`
	Extensions   []extension `json:"extensions"`
	KeyPackages  [][]byte    `json:"key_packages"`
	ForcePath    bool        `json:"force_path"`
	ExternalTree bool        `json:"external_tree"`
}

type createSubgroupResponse struct {
	StateID            uint32 `json:"state_id"`
	Welcome            []byte `json:"welcome"`
	RatchetTree        []byte `json:"ratchet_tree,omitempty"`
	EpochAuthenticator []byte `json:"epoch_authenticator"`
}

type handleBranchRequest struct {
	StateID       uint32 `json:"state_id"`
	TransactionID uint32 `json:"transaction_id"`
	Welcome       []byte `json:"welcome"`
	RatchetTree   []byte `json:"ratchet_tree"`
}

type handleBranchResponse struct {
	StateID            uint32 `json:"state_id"`
	EpochAuthenticator []byte `json:"epoch_authenticator"`
}

type groupStateResponse struct {
	GroupContext []byte `json:"group_context"`
	RatchetTree  []byte `json:"ratchet_tree"`
}

type nameResponse struct {
	Name string `json:"name"`
}

type suitesResponse struct {
	Ciphersuites []uint32 `json:"ciphersuites"`
}

// Request is one line of input: a method of the interop interface and its
// request.
type Request struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// Response is one line of output: the result or an error text.
type Response struct {
	ID     uint64 `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

func call[Req, Resp any](params json.RawMessage, f func(*Req) (*Resp, error)) (any, error) {
	req := new(Req)
	if len(params) > 0 {
		if err := json.Unmarshal(params, req); err != nil {
			return nil, err
		}
	}
	return f(req)
}

// Handle runs one method.
func (c *Client) Handle(method string, params json.RawMessage) (any, error) {
	switch method {
	case "Name":
		return &nameResponse{Name: "kolo-mls"}, nil
	case "SupportedCiphersuites":
		return &suitesResponse{Ciphersuites: []uint32{1}}, nil
	case "CreateGroup":
		return call(params, c.createGroup)
	case "CreateKeyPackage":
		return call(params, c.createKeyPackage)
	case "JoinGroup":
		return call(params, c.joinGroup)
	case "StateAuth":
		return call(params, c.stateAuth)
	case "Export":
		return call(params, c.export)
	case "Protect":
		return call(params, c.protect)
	case "Unprotect":
		return call(params, c.unprotect)
	case "StorePSK":
		return call(params, c.storePSK)
	case "AddProposal":
		return call(params, c.addProposal)
	case "UpdateProposal":
		return call(params, c.updateProposal)
	case "RemoveProposal":
		return call(params, c.removeProposal)
	case "ExternalPSKProposal":
		return call(params, c.externalPSKProposal)
	case "ResumptionPSKProposal":
		return call(params, c.resumptionPSKProposal)
	case "GroupContextExtensionsProposal":
		return call(params, c.groupContextExtensionsProposal)
	case "Commit":
		return call(params, c.commit)
	case "HandleCommit":
		return call(params, c.handleCommit)
	case "HandlePendingCommit":
		return call(params, c.handlePendingCommit)
	case "CreateBranch":
		return call(params, c.createBranch)
	case "HandleBranch":
		return call(params, c.handleBranch)
	case "GroupState":
		return call(params, c.groupState)
	case "Free":
		return call(params, c.free)
	}
	return nil, fmt.Errorf("%w: %s", errUnsupported, method)
}

// Serve answers requests from r on w, one JSON object per line, until r
// ends. A panic in the library is reported as an error starting with PANIC
// and its stack goes to stderr.
func (c *Client) Serve(r io.Reader, w io.Writer, stderr io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 1<<30)
	enc := json.NewEncoder(w)
	for sc.Scan() {
		var req Request
		resp := Response{}
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			resp.Error = err.Error()
		} else {
			resp.ID = req.ID
			res, err := c.safeHandle(req.Method, req.Params, stderr)
			if err != nil {
				resp.Error = err.Error()
			} else {
				resp.Result = res
			}
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (c *Client) safeHandle(method string, params json.RawMessage, stderr io.Writer) (res any, err error) {
	defer func() {
		if p := recover(); p != nil {
			fmt.Fprintf(stderr, "PANIC in %s: %v\n%s", method, p, debug.Stack())
			err = fmt.Errorf("PANIC: %v", p)
		}
	}()
	return c.Handle(method, params)
}
