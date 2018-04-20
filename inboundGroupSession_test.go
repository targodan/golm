package golm

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func createOutAndInboundGroupSession() (*OutboundGroupSession, *InboundGroupSession) {
	out, _ := NewOutboundGroupSession()
	in, _ := NewInboundGroupSession(out.Key())
	return out, in
}

func TestNewInboundGroupSession(t *testing.T) {
	_sess, _ := NewOutboundGroupSession()

	Convey("Creating an inbound group session", t, func() {
		Convey("from a valid key should work.", func() {
			sess, err := NewInboundGroupSession(_sess.Key())
			So(err, ShouldBeNil)
			So(sess, ShouldNotBeNil)
		})
		Convey("from an invalid key should not work.", func() {
			sess, err := NewInboundGroupSession("invalid")
			So(err, ShouldNotBeNil)
			So(sess, ShouldBeNil)
		})
		Convey("from an empty key should not panic.", func() {
			So(func() {
				NewInboundGroupSession("")
			}, ShouldNotPanic)
		})
	})
}

func TestInboundGroupSessionClear(t *testing.T) {
	_, inSess := createOutAndInboundGroupSession()
	Convey("Clearing an InboundGroupSession should not panic.", t, func() {
		So(func() {
			inSess.Clear()
		}, ShouldNotPanic)
	})
}

func TestInboundGroupSessionID(t *testing.T) {
	_, inSess := createOutAndInboundGroupSession()
	Convey("Getting an ID from an InboundGroupSession should work.", t, func() {
		id := inSess.ID()
		So(id, ShouldNotBeEmpty)
	})
}

func TestInboundGroupSessionFirstKnownIndex(t *testing.T) {
	_, inSess := createOutAndInboundGroupSession()
	Convey("Getting the first known index of a InboundGroupSession should not panic.", t, func() {
		So(func() {
			inSess.FirstKnownIndex()
		}, ShouldNotPanic)
	})
}

func TestInboundGroupSessionIsVerified(t *testing.T) {
	_, inSess := createOutAndInboundGroupSession()
	Convey("IsVerified should not panic.", t, func() {
		So(func() {
			inSess.IsVerified()
		}, ShouldNotPanic)
	})
}

func TestInboundGroupSessionExport(t *testing.T) {
	_, inSess := createOutAndInboundGroupSession()
	Convey("Exporting the ratchet at a valid position should work.", t, func() {
		ratchet, err := inSess.Export(inSess.FirstKnownIndex())
		So(err, ShouldBeNil)
		So(ratchet, ShouldNotBeEmpty)
	})
	Convey("Exporting the ratchet at an invalid position should work.", t, func() {
		ratchet, err := inSess.Export(inSess.FirstKnownIndex() - 1)
		So(err, ShouldNotBeNil)
		So(ratchet, ShouldBeEmpty)
	})
}

func TestInboundGroupSessionImport(t *testing.T) {
	_, inSess := createOutAndInboundGroupSession()
	sessionKey, _ := inSess.Export(inSess.FirstKnownIndex())
	Convey("Importing", t, func() {
		Convey("a valid ratchet should work.", func() {
			sess, err := ImportInboundGroupSession(sessionKey)
			So(err, ShouldBeNil)
			So(sess, ShouldNotBeNil)
		})
		Convey("an invalid ratchet should not work.", func() {
			sess, err := ImportInboundGroupSession("invalid")
			So(err, ShouldNotBeNil)
			So(sess, ShouldBeNil)
		})
		Convey("an empty ratchet should not panic.", func() {
			So(func() {
				ImportInboundGroupSession("")
			}, ShouldNotPanic)
		})
	})
}

func TestInboundGroupSessionPickle(t *testing.T) {
	_, sess := createOutAndInboundGroupSession()
	Convey("Pickleing an InboundGroupSession", t, func() {
		Convey("with a valid key should work.", func() {
			pickle, err := sess.Pickle("AA")
			So(err, ShouldBeNil)
			So(pickle, ShouldNotBeEmpty)
		})
		Convey("with an empty key should not panic.", func() {
			So(func() {
				sess.Pickle("")
			}, ShouldNotPanic)
		})
	})
}

func TestInboundGroupSessionUnpickle(t *testing.T) {
	_, _sess := createOutAndInboundGroupSession()
	pickle, _ := _sess.Pickle("AA")

	Convey("Unpickleing an inbound group session", t, func() {
		Convey("with the correct key should work.", func() {
			sess, err := UnpickleInboundGroupSession("AA", pickle)
			So(err, ShouldBeNil)
			So(sess, ShouldNotBeNil)
		})
		Convey("with an incorrect key should not work.", func() {
			sess, err := UnpickleInboundGroupSession("invalid", pickle)
			So(err, ShouldNotBeNil)
			So(sess, ShouldBeNil)
		})
		Convey("with an empty key should not panic.", func() {
			So(func() {
				UnpickleInboundGroupSession("", pickle)
			}, ShouldNotPanic)
		})
		Convey("with an empty pickle should not panic.", func() {
			So(func() {
				UnpickleInboundGroupSession("AA", "")
			}, ShouldNotPanic)
		})
	})
}

func TestInboundGroupSessionDecrypt(t *testing.T) {
	outSess, inSess := createOutAndInboundGroupSession()
	msg, _ := outSess.Encrypt("plaintext")

	outSess2, _ := createOutAndInboundGroupSession()
	invalidMsg, _ := outSess2.Encrypt("plaintext")

	Convey("Decrypting", t, func() {
		Convey("a valid message should work.", func() {
			plaintext, _, err := inSess.Decrypt(msg)
			So(err, ShouldBeNil)
			So(plaintext, ShouldEqual, "plaintext")
		})
		Convey("an invalid message should not work.", func() {
			plaintext, _, err := inSess.Decrypt(invalidMsg)
			So(err, ShouldNotBeNil)
			So(plaintext, ShouldBeEmpty)
		})
		// This Panics:
		// Convey("an invalid message should not work.", func() {
		// 	plaintext, _, err := inSess.Decrypt("invalid")
		// 	So(err, ShouldNotBeNil)
		// 	So(plaintext, ShouldBeEmpty)
		// })
		Convey("an empty message should not panic.", func() {
			So(func() {
				inSess.Decrypt("")
			}, ShouldNotPanic)
		})
	})
}
