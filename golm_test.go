//go:generate mockgen -package golm -destination reader_gen_test.go io Reader
package golm

import (
	"errors"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGetLibraryVersion(t *testing.T) {
	expectedVersion := os.Getenv("GOLM_VERSION")
	if expectedVersion != "" && expectedVersion != "master" {
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

type mockErrorTracker struct {
	Message string
}

func (m mockErrorTracker) lastError() string {
	return m.Message
}

func TestGetError(t *testing.T) {
	ctx := mockErrorTracker{"Some error message."}
	successCtx := mockErrorTracker{"SUCCESS"}

	Convey("On an error code", t, func() {
		Convey("of an actual error, getError...", func() {
			err := getError(ctx, errorCode())
			Convey("should return an error.", func() {
				So(err, ShouldNotBeNil)
			})
			Convey("should return the proper error message.", func() {
				So(err.Error(), ShouldEqual, "Some error message.")
			})
		})
		Convey("of a success, getError...", func() {
			err := getError(successCtx, errorCode())
			Convey("should return nil.", func() {
				So(err, ShouldBeNil)
			})
		})
	})
	Convey("On a non-error code, getError...", t, func() {
		err := getError(ctx, 24)
		Convey("should return nil.", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestPanicOnError(t *testing.T) {
	Convey("On a nil value panicOnError should not panic.", t, func() {
		So(func() {
			panicOnError(nil)
		}, ShouldNotPanic)
	})
	Convey("On an error value panicOnError should panic with the given error.", t, func() {
		err := errors.New("test error")
		So(func() {
			panicOnError(err)
		}, ShouldPanicWith, err)
	})
}
