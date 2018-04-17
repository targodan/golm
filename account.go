package golm

//#include <olm/olm.h>
import "C"
import (
	"crypto/rand"
	"unsafe"
)

type Account struct {
	memory []byte
	ptr    *C.struct_OlmAccount
}

// newAccount initializes a Account.
func newAccount() *Account {
	buf := make([]byte, C.olm_account_size())
	ptr := C.olm_account(unsafe.Pointer(&buf[0]))

	return &Account{
		memory: buf,
		ptr:    ptr,
	}
}

func (a *Account) lastError() string {
	return C.GoString(C.olm_account_last_error(a.ptr))
}

// Clear clears the memory used to back this account.
// Note that once this function was called using the object it
// was called on will panic.
//
// C-Function: olm_clear_inbound_group_session
func (a *Account) Clear() {
	C.olm_clear_account(a.ptr)
}

// NewAccount creates a new account.
//
// C-Function: olm_create_account
func NewAccount() (*Account, error) {
	acc := newAccount()
	reqLength := C.olm_create_account_random_length(acc.ptr)
	randBytes := make([]byte, reqLength)

	n, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}

	result := C.olm_create_account(
		acc.ptr,
		unsafe.Pointer(&randBytes[0]), C.size_t(n),
	)

	err = getError(acc, result)
	if err != nil {
		return nil, err
	}

	return acc, nil
}

// UnpickleAccount loads an account from a pickled base64 string.
// Decrypts the account using the supplied key.
//
// C-Function: olm_unpickle_account
func UnpickleAccount(key, pickle string) (*Account, error) {
	acc := newAccount()

	keyBytes := []byte(key)
	pickleBytes := []byte(pickle)

	result := C.olm_unpickle_account(
		acc.ptr,
		unsafe.Pointer(&keyBytes[0]), C.size_t(len(keyBytes)),
		unsafe.Pointer(&pickleBytes[0]), C.size_t(len(pickleBytes)),
	)

	err := getError(acc, result)
	if err != nil {
		return nil, err
	}

	return acc, nil
}

// Pickle stores the account as a base64 encoded string.
//
// C-Function: olm_pickle_account
func (a *Account) Pickle(key string) (string, error) {
	keyBytes := []byte(key)
	pickleBytes := make([]byte, C.olm_pickle_account_length(a.ptr))

	result := C.olm_pickle_account(
		a.ptr,
		unsafe.Pointer(&keyBytes[0]), C.size_t(len(keyBytes)),
		unsafe.Pointer(&pickleBytes[0]), C.size_t(len(pickleBytes)),
	)

	err := getError(a, result)
	panicOnError(err)

	return string(pickleBytes[:result]), nil
}

// IdentityKeys returns the accounts identity keys.
//
// C-Function: olm_account_identity_keys
func (a *Account) IdentityKeys() (string, error) {
	keyBytes := make([]byte, C.olm_account_identity_keys_length(a.ptr))

	result := C.olm_account_identity_keys(
		a.ptr,
		unsafe.Pointer(&keyBytes[0]), C.size_t(len(keyBytes)),
	)

	err := getError(a, result)
	panicOnError(err)

	// Note: I didn't trim the bytes because the olm-docs don't specify that
	// the return value of olm_account_identity_keys amounts to the keysize
	// on success.
	return string(keyBytes), nil
}

// Sign signs a message with the ed25519 key for this account.
//
// C-Function: olm_account_sign
func (a *Account) Sign(message string) (signature string, err error) {
	messageBytes := []byte(message)
	signatureBytes := make([]byte, C.olm_account_signature_length(a.ptr))

	result := C.olm_account_sign(
		a.ptr,
		unsafe.Pointer(&messageBytes[0]), C.size_t(len(messageBytes)),
		unsafe.Pointer(&signatureBytes[0]), C.size_t(len(signatureBytes)),
	)

	err = getError(a, result)
	panicOnError(err)

	return string(signatureBytes), nil
}

// OneTimeKeys returns the public parts of the unpublished one time keys
// for the account into the one_time_keys output buffer.
//
// The returned data is a JSON-formatted object with the single property
// curve25519, which is itself an object mapping key id to
// base64-encoded Curve25519 key. For example:
//
//     {
//         curve25519: {
//             "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo",
//             "AAAAAB": "LRvjo46L1X2vx69sS9QNFD29HWulxrmW11Up5AfAjgU"
//         }
//     }
//
// C-Function: olm_account_one_time_keys
func (a *Account) OneTimeKeys() string {
	keysBytes := make([]byte, C.olm_account_one_time_keys_length(a.ptr))

	result := C.olm_account_one_time_keys(
		a.ptr,
		unsafe.Pointer(&keysBytes[0]), C.size_t(len(keysBytes)),
	)

	err := getError(a, result)
	// Errors should not happen here.
	panicOnError(err)

	return string(keysBytes)
}

// MarkKeysAsPublished marks the current set of one time keys as being published.
//
// C-Function: olm_account_mark_keys_as_published
func (a *Account) MarkKeysAsPublished() error {
	return getError(a, C.olm_account_mark_keys_as_published(a.ptr))
}

// MaxNumberOfOneTimeKeys returns the largest number of one time keys this account can store.
//
// C-Function: olm_account_max_number_of_one_time_keys
func (a *Account) MaxNumberOfOneTimeKeys() int {
	return int(C.olm_account_max_number_of_one_time_keys(a.ptr))
}

// GenerateOneTimeKeys generates a number of new one time keys. If the total number of keys stored
// by this account exceeds MaxNumberOfOneTimeKeys() then the old keys are discarded.
//
// C-Function: olm_account_generate_one_time_keys
func (a *Account) GenerateOneTimeKeys(numberOfKeys int) error {
	reqLength := C.olm_account_generate_one_time_keys_random_length(a.ptr, C.size_t(numberOfKeys))
	randBytes := make([]byte, reqLength)

	n, err := rand.Read(randBytes)
	if err != nil {
		return err
	}

	result := C.olm_account_generate_one_time_keys(
		a.ptr,
		C.size_t(numberOfKeys),
		unsafe.Pointer(&randBytes[0]), C.size_t(n),
	)

	return getError(a, result)
}

// RemoveOneTimeKeys removes the one time keys that the session used from the account.
//
// C-Function: olm_remove_one_time_keys
func (a *Account) RemoveOneTimeKeys(sess *Session) error {
	result := C.olm_remove_one_time_keys(a.ptr, sess.ptr)
	return getError(a, result)
}
