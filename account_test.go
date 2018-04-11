package golm

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDummy(t *testing.T) {
	// Just a dummy test for now.
	// TODO: Do something meaningful here.

	Convey("Creating an account should work.", t, func() {
		acc := newAccount()
		So(acc.lastError(), ShouldEqual, "SUCCESS")
	})
}
