package golm

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNewUtility(t *testing.T) {
	Convey("Creating a new utility should work.", t, func() {
		util := NewUtility()
		So(util, ShouldNotBeNil)
	})
}

func TestUtilityLastError(t *testing.T) {
	util := NewUtility()
	Convey("LastError should return SUCCESS if no error occured.", t, func() {
		err := util.lastError()
		So(err, ShouldEqual, "SUCCESS")
	})
}

func TestUtilityClear(t *testing.T) {
	util := NewUtility()
	Convey("Clearing the utility should not panic.", t, func() {
		So(func() {
			util.Clear()
		}, ShouldNotPanic)
	})
}

func TestUtilitySHA256(t *testing.T) {
	util := NewUtility()
	Convey("SHA256 should work.", t, func() {
		cipher := util.SHA256("data")
		So(cipher, ShouldNotBeEmpty)
	})
}

func TestUtilityVerify(t *testing.T) {
	util := NewUtility()

	acc, _ := NewAccount()
	key := acc.IdentityKeys().ED25519
	message := "message"
	signature, _ := acc.Sign(message)

	Convey("Verifying a signature", t, func() {
		Convey("with valid parameters should work. ", func() {
			err := util.ED25519Verify(key, message, signature)
			So(err, ShouldBeNil)
		})
		Convey("with an empty key should not panic.", func() {
			So(func() {
				util.ED25519Verify("", message, signature)
			}, ShouldNotPanic)
		})
		Convey("with an empty message should not panic.", func() {
			So(func() {
				util.ED25519Verify(key, "", signature)
			}, ShouldNotPanic)
		})
		Convey("with an empty signature should not panic.", func() {
			So(func() {
				util.ED25519Verify(key, message, "")
			}, ShouldNotPanic)
		})
	})
}
