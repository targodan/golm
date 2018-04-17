// Package golm provides a binding for the crypographic
// library libolm. The library can be found here:
// https://github.com/matrix-org/olm
package golm

//#cgo LDFLAGS: -lolm
//#include <olm/olm.h>
import "C"
import (
	"errors"
	"fmt"
)

// MessageType represents the type of a message.
type MessageType int

const (
	// MessageTypePreKey is the type of a pre key message.
	MessageTypePreKey MessageType = 0
	// MessageTypeMessage is the type of a regular message.
	MessageTypeMessage MessageType = 1
)

// Version represents a version.
type Version struct {
	Major byte
	Minor byte
	Patch byte
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// GetLibraryVersion returns the library version.
//
// C-Function: olm_get_library_version
func GetLibraryVersion() Version {
	var major, minor, patch C.uint8_t

	C.olm_get_library_version(&major, &minor, &patch)
	return Version{
		Major: byte(major),
		Minor: byte(minor),
		Patch: byte(patch),
	}
}

type errorTracker interface {
	lastError() string
}

func errorCode() C.size_t {
	return C.olm_error()
}

func getError(context errorTracker, code C.size_t) error {
	if code != errorCode() {
		return nil
	}

	msg := context.lastError()
	if msg == "SUCCESS" {
		return nil
	}

	return errors.New(msg)
}

// Clearable objects can clear their memory.
type Clearable interface {
	// Clear clears the memory of the object invalidating it as a result.
	Clear()
}

// Pickleable objects can be pickled.
type Pickleable interface {
	// Pickle encodes the object as a base64 string, encrypting it with
	// the supplied key.
	Pickle(key string) (string, error)
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
