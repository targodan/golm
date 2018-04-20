package golm

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

func createOutboundSession() (sess *Session, from, to *Account) {
	from, _ = NewAccount()
	from.GenerateOneTimeKeys(4)

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
				sw := guardRandSource()
				defer sw.Free()

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
				sw := guardRandSource()
				defer sw.Free()
				sess, err := NewOutboundSession(from, "asdf", "asdf")
				So(err, ShouldNotBeNil)
				So(sess, ShouldBeNil)
			})
			Convey("that are empty should not panic.", func() {
				sw := guardRandSource()
				defer sw.Free()
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
		Convey("a non-empty message", func() {
			Convey("with a valid random source should work.", func() {
				sw := guardRandSource()
				defer sw.Free()

				cipher, _, err := sess.Encrypt("some plaintext")

				So(err, ShouldBeNil)
				So(cipher, ShouldNotBeEmpty)
			})
			Convey("with an invalid random source should not work.", func() {
				ctrl := gomock.NewController(t)
				mock := NewMockReader(ctrl)

				mock.EXPECT().Read(gomock.Any()).Return(0, errors.New("some error"))

				sw := switchRandSource(mock)
				defer sw.Revert()

				cipher, _, err := sess.Encrypt("some plaintext")

				So(err, ShouldNotBeNil)
				So(cipher, ShouldBeEmpty)
			})
		})
		Convey("an empty message should not panic.", func() {
			So(func() {
				sess.Encrypt("")
			}, ShouldNotPanic)
		})
	})
}

func TestNewInboundSession(t *testing.T) {
	outSess, _, us := createOutboundSession()
	preKeyMessage, _, _ := outSess.Encrypt("some plaintext")

	Convey("Creating an inbound session", t, func() {
		Convey("from a valid pre key message should work.", func() {
			sess, err := NewInboundSession(us, preKeyMessage)
			So(err, ShouldBeNil)
			So(sess, ShouldNotBeNil)
		})
		Convey("from an invalid pre key message should not work.", func() {
			sess, err := NewInboundSession(us, "not a valid message")
			So(err, ShouldNotBeNil)
			So(sess, ShouldBeNil)
		})
		Convey("from an empty pre key message should not panic.", func() {
			So(func() {
				NewInboundSession(us, "")
			}, ShouldNotPanic)
		})
	})
}

func TestNewInboundSessionFrom(t *testing.T) {
	outSess, them, us := createOutboundSession()
	preKeyMessage, _, _ := outSess.Encrypt("some plaintext")
	theirIdentityKey := them.IdentityKeys().Curve25519

	Convey("Creating an inbound session", t, func() {
		Convey("from a valid pre key message should work.", func() {
			sess, err := NewInboundSessionFrom(us, theirIdentityKey, preKeyMessage)
			So(err, ShouldBeNil)
			So(sess, ShouldNotBeNil)
		})
		Convey("from an invalid pre key message should not work.", func() {
			sess, err := NewInboundSessionFrom(us, theirIdentityKey, "not a valid message")
			So(err, ShouldNotBeNil)
			So(sess, ShouldBeNil)
		})
		Convey("from an empty pre key message should not panic.", func() {
			So(func() {
				NewInboundSessionFrom(us, theirIdentityKey, "")
			}, ShouldNotPanic)
		})
		Convey("from an empty identity key should not panic.", func() {
			So(func() {
				NewInboundSessionFrom(us, "", "message")
			}, ShouldNotPanic)
		})
	})
}

func TestSessionDecrypt(t *testing.T) {
	outSess, them, us := createOutboundSession()
	preKeyMessage, _, _ := outSess.Encrypt("some plaintext")
	theirIdentityKey := them.IdentityKeys().Curve25519
	inSess, _ := NewInboundSessionFrom(us, theirIdentityKey, preKeyMessage)

	cipher, typ, _ := outSess.Encrypt("some plaintext")

	Convey("Decrypting", t, func() {
		Convey("a valid message should work.", func() {
			plaintext, err := inSess.Decrypt(typ, cipher)
			So(err, ShouldBeNil)
			So(plaintext, ShouldEqual, "some plaintext")
		})
		Convey("an invalid message should not work.", func() {
			plaintext, err := inSess.Decrypt(typ, "invalid")
			So(err, ShouldNotBeNil)
			So(plaintext, ShouldBeEmpty)
		})
		Convey("an empty message should not panic.", func() {
			So(func() {
				inSess.Decrypt(typ, "")
			}, ShouldNotPanic)
		})
	})
}

func TestSessionMatchesInboundSession(t *testing.T) {
	outSess, them, us := createOutboundSession()
	preKeyMessage, _, _ := outSess.Encrypt("some plaintext")
	theirIdentityKey := them.IdentityKeys().Curve25519
	inSess, _ := NewInboundSessionFrom(us, theirIdentityKey, preKeyMessage)

	Convey("MatchesInboundSession", t, func() {
		Convey("should not panic", func() {
			Convey("on a valid message.", func() {
				So(func() {
					inSess.MatchesInboundSession(preKeyMessage)
				}, ShouldNotPanic)
			})
			Convey("on an invalid message.", func() {
				So(func() {
					inSess.MatchesInboundSession("0")
				}, ShouldNotPanic)
			})
			Convey("on an empty message.", func() {
				So(func() {
					inSess.MatchesInboundSession("")
				}, ShouldNotPanic)
			})
		})
	})
}

func TestSessionMatchesInboundSessionFrom(t *testing.T) {
	outSess, them, us := createOutboundSession()
	preKeyMessage, _, _ := outSess.Encrypt("some plaintext")
	theirIdentityKey := them.IdentityKeys().Curve25519
	inSess, _ := NewInboundSessionFrom(us, theirIdentityKey, preKeyMessage)

	Convey("MatchesInboundSession", t, func() {
		Convey("should not panic", func() {
			Convey("on a valid key and message.", func() {
				So(func() {
					inSess.MatchesInboundSessionFrom(theirIdentityKey, preKeyMessage)
				}, ShouldNotPanic)
			})
			Convey("on a valid key and an invalid message.", func() {
				So(func() {
					inSess.MatchesInboundSessionFrom(theirIdentityKey, "0")
				}, ShouldNotPanic)
			})
			Convey("on an empty message.", func() {
				So(func() {
					inSess.MatchesInboundSessionFrom(theirIdentityKey, "")
				}, ShouldNotPanic)
			})
			Convey("on an empty key.", func() {
				So(func() {
					inSess.MatchesInboundSessionFrom("", preKeyMessage)
				}, ShouldNotPanic)
			})
		})
	})
}
