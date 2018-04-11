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

// newAccount initializes a new Account.
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

// CreateAccount creates a new account.
//
// C-Function: olm_create_account
func CreateAccount() (*Account, error) {
	acc := newAccount()
	reqLength := C.olm_create_account_random_length(acc.ptr)
	randBytes := make([]byte, reqLength)

	n, err := rand.Read(randBytes)
	if err != nil || n < int(reqLength) {
		return nil, err
	}

	result := C.olm_create_account(
		acc.ptr,
		unsafe.Pointer(&randBytes[0]), C.size_t(len(randBytes)),
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

	keybytes := []byte(key)
	picklebytes := []byte(pickle)

	result := C.olm_unpickle_account(
		acc.ptr,
		unsafe.Pointer(&keybytes[0]), C.size_t(len(keybytes)),
		unsafe.Pointer(&picklebytes[0]), C.size_t(len(picklebytes)),
	)

	err := getError(acc, result)
	if err != nil {
		return nil, err
	}

	return acc, nil
}

// Pickle stores the account as a base64 encoded string.
// C-Function: olm_pickle_account
func (a *Account) Pickle(key string) (string, error) {
	keybytes := []byte(key)
	picklebytes := make([]byte, C.olm_pickle_account_length(a.ptr))

	result := C.olm_pickle_account(
		a.ptr,
		unsafe.Pointer(&keybytes[0]), C.size_t(len(keybytes)),
		unsafe.Pointer(&picklebytes[0]), C.size_t(len(picklebytes)),
	)

	err := getError(a, result)
	if err != nil {
		return "", err
	}

	return string(picklebytes[:result]), nil
}
