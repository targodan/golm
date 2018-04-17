package golm

//#include <olm/olm.h>
//#include <stdlib.h>
//#include <string.h>
import "C"
import "unsafe"

type OutboundGroupSession struct {
	memory []byte
	ptr    *C.OlmOutboundGroupSession
}

func newOutboundGroupSession() *OutboundGroupSession {
	s := &OutboundGroupSession{}

	s.memory = make([]byte, C.olm_outbound_group_session_size())
	s.ptr = C.olm_outbound_group_session(unsafe.Pointer(&s.memory[0]))

	return s
}

// NewOutboundGroupSession starts a new outbound group session from a key exported from
// an outbound group session key.
//
// C-Function: olm_init_outbound_group_session
func NewOutboundGroupSession(sessionKey string) (*OutboundGroupSession, error) {
	s := newOutboundGroupSession()

	sessionKeyBytes := []byte(sessionKey)

	result := C.olm_init_outbound_group_session(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&sessionKeyBytes[0])), C.size_t(len(sessionKeyBytes)),
	)

	err := getError(s, result)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *OutboundGroupSession) lastError() string {
	return C.GoString(C.olm_outbound_group_session_last_error(s.ptr))
}

// Clear clears the memory used to back this group session.
// Note that once this function was called using the object it
// was called on will panic.
//
// C-Function: olm_clear_outbound_group_session
func (s *OutboundGroupSession) Clear() {
	C.olm_clear_outbound_group_session(s.ptr)
}

// Pickle stores a group session as a base64 string. Encrypts the session using the
// supplied key.
//
// C-Function: olm_pickle_outbound_group_session
func (s *OutboundGroupSession) Pickle(key string) (string, error) {
	keyBytes := []byte(key)
	pickleBytes := make([]byte, C.olm_pickle_outbound_group_session_length(s.ptr))

	result := C.olm_pickle_outbound_group_session(
		s.ptr,
		unsafe.Pointer(&keyBytes[0]), C.size_t(len(keyBytes)),
		unsafe.Pointer(&pickleBytes[0]), C.size_t(len(pickleBytes)),
	)

	err := getError(s, result)
	if err != nil {
		return "", err
	}

	return string(pickleBytes[:result]), nil
}

// UnpickleOutboundGroupSession loads an group session from a pickled base64 string.
// Decrypts the session using the supplied key.
//
// C-Function: olm_unpickle_outbound_group_session
func UnpickleOutboundGroupSession(key, pickle string) (*OutboundGroupSession, error) {
	s := newOutboundGroupSession()

	keyBytes := []byte(key)
	pickleBytes := []byte(pickle)

	result := C.olm_unpickle_outbound_group_session(
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

// ID returns a base64-encoded identifier for this session.
//
// C-Function: olm_outbound_group_session_id
func (s *OutboundGroupSession) ID() string {
	idBytes := make([]byte, C.olm_outbound_group_session_id_length(s.ptr))

	result := C.olm_outbound_group_session_id(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&idBytes[0])), C.size_t(len(idBytes)),
	)

	err := getError(s, result)
	if err != nil {
		// Should never happen.
		panic(err)
	}

	return string(idBytes)
}

// Encrypt encrypts some plain-text.
//
// C-Function: olm_group_encrypt
func (s *OutboundGroupSession) Encrypt(plaintext string) string {
	plainBytes := []byte(plaintext)
	messageBytes := make([]byte, C.olm_group_encrypt_message_length(s.ptr, C.size_t(len(plainBytes))))

	result := C.olm_group_encrypt(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&plainBytes[0])), C.size_t(len(plainBytes)),
		(*C.uint8_t)(unsafe.Pointer(&messageBytes[0])), C.size_t(len(messageBytes)),
	)

	err := getError(s, result)
	if err != nil {
		// Should never happen.
		panic(err)
	}

	return string(messageBytes[:result])
}

// MessageIndex returns the current message index for this session.
//
// Each message is sent with an increasing index; this returns the index for
// the next message.
//
// C-Function: olm_outbound_group_session_message_index
func (s *OutboundGroupSession) MessageIndex() uint32 {
	return uint32(C.olm_outbound_group_session_message_index(s.ptr))
}

// Key returns the base64-encoded current ratchet key for this session.
//
// Each message is sent with a different ratchet key. This function returns
// the ratchet key that will be used for the next message.
//
// C-Function:
func (s *OutboundGroupSession) Key() string {
	keyBytes := make([]byte, C.olm_outbound_group_session_key_length(s.ptr))

	result := C.olm_outbound_group_session_key(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&keyBytes[0])), C.size_t(len(keyBytes)),
	)

	err := getError(s, result)
	if err != nil {
		// Should never happen.
		panic(err)
	}

	return string(keyBytes[:result])
}
