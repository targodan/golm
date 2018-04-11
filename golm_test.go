package golm

import (
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGetLibraryVersion(t *testing.T) {
	expectedVersion := os.Getenv("GOLM_EXPECTED_VERSION")
	if expectedVersion != "" {
		// Check against exact version
		Convey("GetLibraryVersion should match the expected version.", t, func() {
			So(GetLibraryVersion().String(), ShouldEqual, expectedVersion)
		})
	} else {
		Convey("GetLibraryVersion should not return an empty version.", t, func() {
			So(GetLibraryVersion().String(), ShouldNotEqual, "0.0.0")
		})
	}
}
