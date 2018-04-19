package golm

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestOneTimeKeysCurve(t *testing.T) {
	keys := &OneTimeKeys{
		Curve25519: map[string]string{
			"A": "X",
			"B": "Y",
			"C": "Z",
		},
	}

	Convey("Retreiving the an existing curve should work.", t, func() {
		So(keys.Curve(0), ShouldNotBeEmpty)
		So(keys.Curve(1), ShouldNotBeEmpty)
		So(keys.Curve(2), ShouldNotBeEmpty)
	})
	Convey("Retreiving keys out of bounds should not work.", t, func() {
		So(keys.Curve(-1), ShouldBeEmpty)
		So(keys.Curve(3), ShouldBeEmpty)
	})
}

func TestOneTimeKeysID(t *testing.T) {
	keys := &OneTimeKeys{
		Curve25519: map[string]string{
			"A": "X",
			"B": "Y",
			"C": "Z",
		},
	}

	Convey("Retreiving the ID of an existing curve should work.", t, func() {
		So(keys.ID(0), ShouldNotBeEmpty)
		So(keys.ID(1), ShouldNotBeEmpty)
		So(keys.ID(2), ShouldNotBeEmpty)
	})
	Convey("Retreiving the ID of out of bounds keys should not work.", t, func() {
		So(keys.ID(-1), ShouldBeEmpty)
		So(keys.ID(3), ShouldBeEmpty)
	})
}

func TestOneTimeKeysSize(t *testing.T) {
	keys := &OneTimeKeys{
		Curve25519: map[string]string{
			"A": "X",
			"B": "Y",
			"C": "Z",
		},
	}

	Convey("Size should return the correct size.", t, func() {
		So(keys.Size(), ShouldEqual, 3)
	})
}
