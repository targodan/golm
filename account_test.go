package golm

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewAccount(t *testing.T) {
	Convey("Creating an account with enough random should work.", t, func() {
		sw := guardRandSource()
		defer sw.Free()

		acc, err := NewAccount()
		So(err, ShouldBeNil)
		So(acc.lastError(), ShouldEqual, "SUCCESS")
	})
	Convey("Creating an account with the random source faulty should error.", t, func() {
		ctrl := gomock.NewController(t)
		mock := NewMockReader(ctrl)

		mock.EXPECT().Read(gomock.Any()).Return(0, errors.New("some error"))

		sw := switchRandSource(mock)
		defer sw.Revert()

		acc, err := NewAccount()
		So(err, ShouldNotBeNil)
		So(acc, ShouldBeNil)
	})
}

func TestClearAccount(t *testing.T) {
	Convey("Clearing should work.", t, func() {
		acc, _ := NewAccount()
		So(func() {
			acc.Clear()
		}, ShouldNotPanic)
	})
}

func TestPickleAccount(t *testing.T) {
	Convey("Pickleing should work.", t, func() {
		acc, _ := NewAccount()
		pickled, err := acc.Pickle("AA")
		So(err, ShouldBeNil)
		So(pickled, ShouldNotEqual, "")
	})
	Convey("An empty key should not panic.", t, func() {
		acc, _ := NewAccount()
		So(func() {
			acc.Pickle("")
		}, ShouldNotPanic)
	})
}

func TestUnpickleAccount(t *testing.T) {
	origAcc, _ := NewAccount()
	pickled, _ := origAcc.Pickle("AA")

	Convey("Unpickleing with the correct key should work.", t, func() {
		acc, err := UnpickleAccount("AA", pickled)
		So(err, ShouldBeNil)
		So(acc, ShouldNotBeNil)
	})
	Convey("Unpickleing with an incorrect key should not work.", t, func() {
		acc, err := UnpickleAccount("FF", pickled)
		So(acc, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})
	Convey("Unpickleing with an empty key should not panic.", t, func() {
		So(func() {
			UnpickleAccount("", pickled)
		}, ShouldNotPanic)
	})
}

func TestAccountIdentityKeys(t *testing.T) {
	Convey("IdentityKeys should work on an account.", t, func() {
		acc, _ := NewAccount()
		keys := acc.IdentityKeys()

		So(keys, ShouldNotBeEmpty)
	})
}

func TestAccountSign(t *testing.T) {
	Convey("Signing a message should work.", t, func() {
		acc, _ := NewAccount()
		signature, err := acc.Sign("some message")
		So(signature, ShouldNotBeEmpty)
		So(err, ShouldBeNil)
	})
	Convey("Signing an empty message should not panic.", t, func() {
		acc, _ := NewAccount()
		So(func() {
			acc.Sign("")
		}, ShouldNotPanic)
	})
}

func TestAccountOneTimeKeys(t *testing.T) {
	Convey("Requesting the one time keys should work.", t, func() {
		acc, _ := NewAccount()
		keys := acc.OneTimeKeys()
		So(keys, ShouldNotBeEmpty)
	})
}

func TestAccountMarkKeysAsPublished(t *testing.T) {
	Convey("Marking the keys as published should work.", t, func() {
		acc, _ := NewAccount()
		err := acc.MarkKeysAsPublished()
		So(err, ShouldBeNil)
	})
}

func TestAccountMaxOneTimeKeys(t *testing.T) {
	Convey("Requesting the max amount of one time keys should work.", t, func() {
		acc, _ := NewAccount()
		num := acc.MaxNumberOfOneTimeKeys()
		So(num, ShouldBeGreaterThan, 0)
	})
}

func TestAccountGenerateOneTimeKeys(t *testing.T) {
	Convey("Generating more one time keys with a valid random source should work.", t, func() {
		sw := guardRandSource()
		defer sw.Free()

		acc, _ := NewAccount()
		err := acc.GenerateOneTimeKeys(1)
		So(err, ShouldBeNil)
	})
	Convey("Generating more one time keys with a invalid random source should not work.", t, func() {
		ctrl := gomock.NewController(t)
		mock := NewMockReader(ctrl)

		mock.EXPECT().Read(gomock.Any()).Return(0, errors.New("some error"))

		acc, _ := NewAccount()

		sw := switchRandSource(mock)
		defer sw.Revert()

		err := acc.GenerateOneTimeKeys(1)
		So(err, ShouldNotBeNil)
	})
}
