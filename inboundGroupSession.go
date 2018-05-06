package golm

//#include <olm/olm.h>
//#include <stdlib.h>
//#include <string.h>
import "C"
import (
	"errors"
	"unsafe"
)

// InboundGroupSession represents an inbound group session and its
// cryptographic keys.
type InboundGroupSession struct {
	memory []byte
	ptr    *C.OlmInboundGroupSession
}

func newInboundGroupSession() *InboundGroupSession {
	s := &InboundGroupSession{}

	s.memory = make([]byte, C.olm_inbound_group_session_size())
	s.ptr = C.olm_inbound_group_session(unsafe.Pointer(&s.memory[0]))

	return s
}

// NewInboundGroupSession starts a new inbound group session from a key exported from
// an outbound group session key.
//
// C-Function: olm_init_inbound_group_session
func NewInboundGroupSession(sessionKey string) (*InboundGroupSession, error) {
	if sessionKey == "" {
		return nil, errors.New("session key must not be empty")
	}

	s := newInboundGroupSession()

	sessionKeyBytes := []byte(sessionKey)

	result := C.olm_init_inbound_group_session(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&sessionKeyBytes[0])), C.size_t(len(sessionKeyBytes)),
	)

	err := getError(s, result)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *InboundGroupSession) lastError() string {
	return C.GoString(C.olm_inbound_group_session_last_error(s.ptr))
}

// Clear clears the memory used to back this group session.
// Note that once this function was called using the object it
// was called on will panic.
//
// C-Function: olm_clear_inbound_group_session
func (s *InboundGroupSession) Clear() {
	C.olm_clear_inbound_group_session(s.ptr)
}

// Pickle stores a group session as a base64 string. Encrypts the session using the
// supplied key.
//
// C-Function: olm_pickle_inbound_group_session
func (s *InboundGroupSession) Pickle(key string) (string, error) {
	if key == "" {
		return "", errors.New("key must not be empty")
	}

	keyBytes := []byte(key)
	pickleBytes := make([]byte, C.olm_pickle_inbound_group_session_length(s.ptr))

	result := C.olm_pickle_inbound_group_session(
		s.ptr,
		unsafe.Pointer(&keyBytes[0]), C.size_t(len(keyBytes)),
		unsafe.Pointer(&pickleBytes[0]), C.size_t(len(pickleBytes)),
	)

	err := getError(s, result)
	panicOnError(err)

	return string(pickleBytes[:result]), nil
}

// UnpickleInboundGroupSession loads an group session from a pickled base64 string.
// Decrypts the session using the supplied key.
//
// C-Function: olm_unpickle_inbound_group_session
func UnpickleInboundGroupSession(key, pickle string) (*InboundGroupSession, error) {
	if key == "" {
		return nil, errors.New("key must not be empty")
	}
	if pickle == "" {
		return nil, errors.New("pickle must not be empty")
	}

	s := newInboundGroupSession()

	keyBytes := []byte(key)
	pickleBytes := []byte(pickle)

	result := C.olm_unpickle_inbound_group_session(
		s.ptr,
		unsafe.Pointer(&keyBytes[0]), C.size_t(len(keyBytes)),
		unsafe.Pointer(&pickleBytes[0]), C.size_t(len(pickleBytes)),
	)

	err := getError(s, result)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// ImportInboundGroupSession imports an inbound group session, from a previous export.
//
// C-Function: olm_import_inbound_group_session
func ImportInboundGroupSession(sessionKey string) (*InboundGroupSession, error) {
	if sessionKey == "" {
		return nil, errors.New("session key must not be empty")
	}

	s := newInboundGroupSession()

	sessionKeyBytes := []byte(sessionKey)

	result := C.olm_import_inbound_group_session(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&sessionKeyBytes[0])), C.size_t(len(sessionKeyBytes)),
	)

	err := getError(s, result)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Decrypt decrypts a message.
//
// C-Function: olm_group_decrypt
func (s *InboundGroupSession) Decrypt(message string) (plaintext string, index uint32, err error) {
	if message == "" {
		return "", 0, errors.New("message must not be empty")
	}

	messageBytes := []byte(message)
	unsignedMsgBytes := (*C.uint8_t)(unsafe.Pointer(&messageBytes[0]))
	messageSize := C.size_t(len(messageBytes))

	// This destroys the input buffer...
	plaintextLength := C.olm_group_decrypt_max_plaintext_length(s.ptr, unsignedMsgBytes, messageSize)
	plaintextBytes := make([]byte, plaintextLength)
	unsignedPlainBytes := (*C.uint8_t)(unsafe.Pointer(&plaintextBytes[0]))

	// ...hence we need to create it again.
	messageBytes = []byte(message)
	unsignedMsgBytes = (*C.uint8_t)(unsafe.Pointer(&messageBytes[0]))

	result := C.olm_group_decrypt(
		s.ptr,
		unsignedMsgBytes, messageSize,
		unsignedPlainBytes, plaintextLength,
		(*C.uint32_t)(&index),
	)

	err = getError(s, result)
	if err != nil {
		return
	}

	return string(plaintextBytes[:result]), index, nil
}

// ID returns a base64-encoded identifier for this session.
//
// C-Function: olm_inbound_group_session_id
func (s *InboundGroupSession) ID() string {
	idBytes := make([]byte, C.olm_inbound_group_session_id_length(s.ptr))

	result := C.olm_inbound_group_session_id(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&idBytes[0])), C.size_t(len(idBytes)),
	)

	err := getError(s, result)
	panicOnError(err)

	return string(idBytes)
}

// FirstKnownIndex returns the first message index we know how to decrypt.
//
// C-Function: olm_inbound_group_session_first_known_index
func (s *InboundGroupSession) FirstKnownIndex() uint32 {
	return uint32(C.olm_inbound_group_session_first_known_index(s.ptr))
}

// IsVerified returns true if the session has been verified as a valid session.
//
// A session is verified either because the original session share was signed,
// or because we have subsequently successfully decrypted a message.
//
// C-Function: olm_inbound_group_session_is_verified
func (s *InboundGroupSession) IsVerified() bool {
	return C.olm_inbound_group_session_is_verified(s.ptr) != 0
}

// Export exports the base64-encoded ratchet key for this session, at the given index,
// in a format which can be used by ImportInboundGroupSession.
//
// C-Function: olm_export_inbound_group_session
func (s *InboundGroupSession) Export(messageIndex uint32) (string, error) {
	keyBytes := make([]byte, C.olm_export_inbound_group_session_length(s.ptr))

	result := C.olm_export_inbound_group_session(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&keyBytes[0])), C.size_t(len(keyBytes)),
		C.uint32_t(messageIndex),
	)

	err := getError(s, result)
	if err != nil {
		return "", err
	}

	return string(keyBytes[:result]), nil
}
