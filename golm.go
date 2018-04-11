// Package golm provides a binding for the crypographic
// library libolm. The library can be found here:
// https://github.com/matrix-org/olm
package golm

//#cgo LDFLAGS: -lolm -Wl,-rpath -Wl,/usr/local/lib
//#include <olm/olm.h>
import "C"
import (
	"errors"
	"fmt"
)

const (
	MessageTypePreKey  = 0
	MessageTypeMessage = 1
)

type Version struct {
	Major byte
	Minor byte
	Patch byte
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

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

func getError(context errorTracker, code C.size_t) error {
	if code != C.olm_error() {
		return nil
	}

	msg := context.lastError()
	if msg == "SUCCESS" {
		return nil
	}

	return errors.New(msg)
}
