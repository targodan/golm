package golm

//#include <olm/olm.h>
import "C"
import (
	"unsafe"
)

type Utility struct {
	memory []byte
	ptr    *C.struct_OlmUtility
}

// newUtility initializes a Utility.
func newUtility() *Utility {
	buf := make([]byte, C.olm_utility_size())
	ptr := C.olm_utility(unsafe.Pointer(&buf[0]))

	return &Utility{
		memory: buf,
		ptr:    ptr,
	}
}

func (u *Utility) lastError() string {
	return C.GoString(C.olm_utility_last_error(u.ptr))
}

// SHA256 calculates the SHA-256 hash of the input and encodes it as base64.
//
// C-Function: olm_sha256
func (u *Utility) SHA256(input string) (string, error) {
	inputBytes := []byte(input)
	outputBytes := make([]byte, C.olm_sha256_length(u.ptr))

	result := C.olm_sha256(
		u.ptr,
		unsafe.Pointer(&inputBytes[0]), C.size_t(len(inputBytes)),
		unsafe.Pointer(&outputBytes[0]), C.size_t(len(outputBytes)),
	)

	err := getError(u, result)
	if err != nil {
		return "", err
	}

	return string(outputBytes), nil
}

// ED25519Verify verifies an ed25519 signature.
//
// C-Function: olm_ed25519_verify
func (u *Utility) ED25519Verify(key, message, signature string) error {
	keyBytes := []byte(key)
	messageBytes := []byte(message)
	signatureBytes := []byte(signature)

	result := C.olm_ed25519_verify(
		u.ptr,
		unsafe.Pointer(&keyBytes[0]), C.size_t(len(keyBytes)),
		unsafe.Pointer(&messageBytes[0]), C.size_t(len(messageBytes)),
		unsafe.Pointer(&signatureBytes[0]), C.size_t(len(signatureBytes)),
	)

	return getError(u, result)
}
