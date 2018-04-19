package golm

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

func createOutboundSession() (sess *Session, from, to *Account) {
	from, _ = NewAccount()
	to, _ = NewAccount()
	to.GenerateOneTimeKeys(4)
	toIdentity := to.IdentityKeys()
	toOneTimeKeys := to.OneTimeKeys()
	sess, _ = NewOutboundSession(from, toIdentity.Curve25519, toOneTimeKeys.Curve(0))
	return
}

func TestNewOutboundSession(t *testing.T) {
	from, _ := NewAccount()
	to, _ := NewAccount()
	to.GenerateOneTimeKeys(4)

	Convey("Creating an outbound session", t, func() {
		Convey("with valid keys", func() {
			toIdentity := to.IdentityKeys()
			toOneTimeKeys := to.OneTimeKeys()
			Convey("and valid random data should work.", func() {

				sess, err := NewOutboundSession(from, toIdentity.Curve25519, toOneTimeKeys.Curve(0))
				So(err, ShouldBeNil)
				So(sess, ShouldNotBeNil)
			})
			Convey("and invalid random data should error.", func() {
				ctrl := gomock.NewController(t)
				mock := NewMockReader(ctrl)

				mock.EXPECT().Read(gomock.Any()).Return(0, errors.New("some error"))

				sw := switchRandSource(mock)
				defer sw.Revert()

				sess, err := NewOutboundSession(from, toIdentity.Curve25519, toOneTimeKeys.Curve(0))
				So(err, ShouldNotBeNil)
				So(sess, ShouldBeNil)
			})
		})
		Convey("with invalid keys", func() {
			Convey("that are non-empty should error.", func() {
				sess, err := NewOutboundSession(from, "asdf", "asdf")
				So(err, ShouldNotBeNil)
				So(sess, ShouldBeNil)
			})
			Convey("that are empty should not panic.", func() {
				So(func() {
					NewOutboundSession(from, "", "")
				}, ShouldNotPanic)
			})
		})
	})
}

func TestSessionClear(t *testing.T) {
	sess, _, _ := createOutboundSession()

	Convey("Clearing a session should not panic.", t, func() {
		So(func() {
			sess.Clear()
		}, ShouldNotPanic)
	})
}

func TestSessionPickle(t *testing.T) {
	sess, _, _ := createOutboundSession()

	Convey("Pickleing", t, func() {
		Convey("with a valid key should work.", func() {
			pickled, err := sess.Pickle("AA")
			So(pickled, ShouldNotBeEmpty)
			So(err, ShouldBeNil)
		})
		Convey("with an empty key should not panic.", func() {
			So(func() {
				sess.Pickle("")
			}, ShouldNotPanic)
		})
	})
}

func TestSessionUnpickle(t *testing.T) {
	sess, _, _ := createOutboundSession()
	pickle, _ := sess.Pickle("AA")

	Convey("Unpickleing", t, func() {
		Convey("a valid pickle", func() {
			Convey("with the correct key should work.", func() {
				s, err := UnpickleSession("AA", pickle)
				So(s, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})
			Convey("with an incorrect key should not work.", func() {
				s, err := UnpickleSession("FF", pickle)
				So(s, ShouldBeNil)
				So(err, ShouldNotBeNil)
			})
			Convey("with an empty key should not panic.", func() {
				So(func() {
					UnpickleSession("", pickle)
				}, ShouldNotPanic)
			})
		})
		// The following case causes a segfault but we can't do anything about that.
		// Convey("an invalid pickle should not work.", func() {
		// 	s, err := UnpickleSession("AA", "asdf")
		// 	So(s, ShouldBeNil)
		// 	So(err, ShouldNotBeNil)
		// })
		Convey("an empty pickle should not panic.", func() {
			So(func() {
				UnpickleSession("AA", "")
			}, ShouldNotPanic)
		})
	})
}

func TestSessionID(t *testing.T) {
	sess, _, _ := createOutboundSession()

	Convey("Getting an ID should work.", t, func() {
		id := sess.ID()
		So(id, ShouldNotBeEmpty)
	})
}

func TestSessionHasReceivedMessage(t *testing.T) {
	sess, _, _ := createOutboundSession()

	Convey("Querying if the session has received messages should not panic.", t, func() {
		So(func() {
			sess.HasReceivedMessage()
		}, ShouldNotPanic)
	})
}

func TestSessionEcrypt(t *testing.T) {
	sess, _, _ := createOutboundSession()

	Convey("Encrypting", t, func() {
		Convey("with a valid random source", func() {
			Convey("a non-empty message should work.", func() {
				cipher, t, err := sess.Encrypt("some plaintext")

				fmt.Println(cipher)
				fmt.Println(t)
				fmt.Println(err)

				So(err, ShouldBeNil)
				So(cipher, ShouldNotBeEmpty)
			})
		})
	})
}
