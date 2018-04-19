package golm

//#include <olm/olm.h>
//#include <string.h>
import "C"
import (
	"crypto/rand"
	"errors"
	"unsafe"
)

// Session represents a session and its cryptographic keys.
type Session struct {
	memory []byte
	ptr    *C.struct_OlmSession
}

// newSession initializes a Session.
func newSession() *Session {
	buf := make([]byte, C.olm_session_size())
	ptr := C.olm_session(unsafe.Pointer(&buf[0]))

	return &Session{
		memory: buf,
		ptr:    ptr,
	}
}

func (s *Session) lastError() string {
	return C.GoString(C.olm_session_last_error(s.ptr))
}

// Clear clears the memory used to back this Session.
// Note that once this function was called using the object it
// was called on will panic.
//
// C-Function: olm_clear_inbound_group_session
func (s *Session) Clear() {
	C.olm_clear_session(s.ptr)
}

// NewOutboundSession creates a new out-bound session for sending messages to a given identityKey
// and oneTimeKey.
//
// C-Function: olm_create_inbound_session
func NewOutboundSession(account *Account, theirIdentityKey, theirOneTimeKey string) (*Session, error) {
	if theirIdentityKey == "" || theirOneTimeKey == "" {
		return nil, errors.New("the keys must not be empty")
	}

	sess := newSession()

	identKeyBytes := []byte(theirIdentityKey)
	oneTimeKeyBytes := []byte(theirOneTimeKey)
	randomBytes := make([]byte, C.olm_create_outbound_session_random_length(sess.ptr))

	n, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	result := C.olm_create_outbound_session(
		sess.ptr,
		account.ptr,
		unsafe.Pointer(&identKeyBytes[0]), C.size_t(len(identKeyBytes)),
		unsafe.Pointer(&oneTimeKeyBytes[0]), C.size_t(len(oneTimeKeyBytes)),
		unsafe.Pointer(&randomBytes[0]), C.size_t(n),
	)

	err = getError(sess, result)
	if err != nil {
		return nil, err
	}

	return sess, nil
}

// NewInboundSession creates a new in-bound session for sending/receiving messages from an
// incoming PRE_KEY message.
//
// C-Function: olm_create_inbound_session
func NewInboundSession(account *Account, oneTimeKeyMessage string) (*Session, error) {
	sess := newSession()

	keyMessageBytes := []byte(oneTimeKeyMessage)

	result := C.olm_create_inbound_session(
		sess.ptr,
		account.ptr,
		unsafe.Pointer(&keyMessageBytes[0]), C.size_t(len(keyMessageBytes)),
	)

	err := getError(sess, result)
	if err != nil {
		return nil, err
	}

	return sess, nil
}

// NewInboundSessionFrom creates a new in-bound session for sending/receiving messages from an
// incoming PRE_KEY message.
//
// C-Function: olm_create_inbound_session_from
func NewInboundSessionFrom(account *Account, theirIdentityKey string, oneTimeKeyMessage string) (*Session, error) {
	sess := newSession()

	identKeyBytes := []byte(theirIdentityKey)
	keyMessageBytes := []byte(oneTimeKeyMessage)

	result := C.olm_create_inbound_session_from(
		sess.ptr,
		account.ptr,
		unsafe.Pointer(&identKeyBytes[0]), C.size_t(len(identKeyBytes)),
		unsafe.Pointer(&keyMessageBytes[0]), C.size_t(len(keyMessageBytes)),
	)

	err := getError(sess, result)
	if err != nil {
		return nil, err
	}

	return sess, nil
}

// UnpickleSession loads an session from a pickled base64 string.
// Decrypts the account using the supplied key.
//
// C-Function: olm_unpickle_session
func UnpickleSession(key, pickle string) (*Session, error) {
	if key == "" {
		return nil, errors.New("key must not be empty")
	}
	if pickle == "" {
		return nil, errors.New("pickle must not be empty")
	}

	sess := newSession()

	keyBytes := []byte(key)
	pickleBytes := []byte(pickle)

	result := C.olm_unpickle_session(
		sess.ptr,
		unsafe.Pointer(&keyBytes[0]), C.size_t(len(keyBytes)),
		unsafe.Pointer(&pickleBytes[0]), C.size_t(len(pickleBytes)),
	)

	err := getError(sess, result)
	if err != nil {
		return nil, err
	}

	return sess, nil
}

// Pickle stores a session as a base64 string. Encrypts the session using the
// supplied key.
//
// C-Function: olm_pickle_session
func (s *Session) Pickle(key string) (string, error) {
	if key == "" {
		return "", errors.New("key must not be empty")
	}

	keyBytes := []byte(key)
	pickleBytes := make([]byte, C.olm_pickle_session_length(s.ptr))

	result := C.olm_pickle_session(
		s.ptr,
		unsafe.Pointer(&keyBytes[0]), C.size_t(len(keyBytes)),
		unsafe.Pointer(&pickleBytes[0]), C.size_t(len(pickleBytes)),
	)

	err := getError(s, result)
	panicOnError(err)

	return string(pickleBytes[:result]), nil
}

// ID returns an identifier for this session. Will be the same for both ends of the
// conversation.
//
// C-Function: olm_session_id
func (s *Session) ID() string {
	idBytes := make([]byte, C.olm_session_id_length(s.ptr))

	result := C.olm_session_id(
		s.ptr,
		unsafe.Pointer(&idBytes[0]), C.size_t(len(idBytes)),
	)

	err := getError(s, result)
	panicOnError(err)

	// Note: I didn't trim the bytes because the olm-docs don't specify that
	// the return value of olm_account_identity_keys amounts to the keysize
	// on success.
	return string(idBytes)
}

// HasReceivedMessage returns true if this session has received a message.
//
// C-Function: olm_session_has_received_message
func (s *Session) HasReceivedMessage() bool {
	return C.olm_session_has_received_message(s.ptr) != 0
}

// MatchesInboundSession checks if the PRE_KEY is for this in-bound session. This can happen if multiple messages are sent to this account before this account sends a message reply.
//
// C-Function: olm_matches_inbound_session
func (s *Session) MatchesInboundSession(oneTimeKeyMessage string) (bool, error) {
	keyBytes := []byte(oneTimeKeyMessage)

	result := C.olm_matches_inbound_session(
		s.ptr,
		unsafe.Pointer(&keyBytes[0]), C.size_t(len(keyBytes)),
	)

	err := getError(s, result)
	if err != nil {
		return false, err
	}

	return result != 0, nil
}

// MatchesInboundSessionFrom checks if the PRE_KEY is for this in-bound session. This can happen if multiple messages are sent to this account before this account sends a message reply.
//
// C-Function: olm_matches_inbound_session_from
func (s *Session) MatchesInboundSessionFrom(theirIdentityKey, oneTimeKeyMessage string) (bool, error) {
	identKeyBytes := []byte(theirIdentityKey)
	keyMessageBytes := []byte(oneTimeKeyMessage)

	result := C.olm_matches_inbound_session_from(
		s.ptr,
		unsafe.Pointer(&identKeyBytes[0]), C.size_t(len(identKeyBytes)),
		unsafe.Pointer(&keyMessageBytes[0]), C.size_t(len(keyMessageBytes)),
	)

	err := getError(s, result)
	if err != nil {
		return false, err
	}

	return result != 0, nil
}

// Encrypt encrypts a message using the session.
//
// C-Function: olm_encrypt
func (s *Session) Encrypt(plaintext string) (string, MessageType, error) {
	if plaintext == "" {
		return "", -1, errors.New("plaintext must not be empty")
	}

	msgType := C.olm_encrypt_message_type(s.ptr)

	plaintextBytes := []byte(plaintext)

	randomBytes := make([]byte, C.olm_encrypt_random_length(s.ptr))
	messageBytes := make([]byte, C.olm_encrypt_message_length(s.ptr, C.size_t(len(plaintextBytes))))

	plaintextCStr := C.CString(plaintext)

	n, err := rand.Read(randomBytes)
	if err != nil {
		return "", -1, err
	}

	result := C.olm_encrypt(
		s.ptr,
		unsafe.Pointer(plaintextCStr), C.size_t(len(plaintextBytes)),
		// unsafe.Pointer(&plaintextBytes[0]), C.size_t(len(plaintextBytes)),
		unsafe.Pointer(&randomBytes[0]), C.size_t(n),
		unsafe.Pointer(&messageBytes[0]), C.size_t(len(messageBytes)),
	)

	err = getError(s, result)
	if err != nil {
		return "", -1, err
	}

	return string(messageBytes[:result]), MessageType(msgType), nil
}

// Decrypt decrypts a message using the session.
//
// TODO: Find out what "The input buffer is destroyed." means in this context and
// if we need to handle this somehow.
//
// C-Function: olm_decrypt
func (s *Session) Decrypt(typ MessageType, message string) (string, error) {
	messageBytes := []byte(message)
	plaintextBytes := make([]byte, C.olm_decrypt_max_plaintext_length(s.ptr, C.size_t(typ), unsafe.Pointer(&messageBytes[0]), C.size_t(len(messageBytes))))

	result := C.olm_decrypt(
		s.ptr,
		C.size_t(typ),
		unsafe.Pointer(&messageBytes[0]), C.size_t(len(messageBytes)),
		unsafe.Pointer(&plaintextBytes[0]), C.size_t(len(plaintextBytes)),
	)

	err := getError(s, result)
	if err != nil {
		return "", err
	}

	return string(plaintextBytes[:result]), nil
}
