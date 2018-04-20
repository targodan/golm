package golm

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
)

func TestNewOutboundGroupSession(t *testing.T) {
	Convey("Creating a new OutboundGroupSession", t, func() {
		Convey("with a valid random source should work.", func() {
			sw := guardRandSource()
			defer sw.Free()

			sess, err := NewOutboundGroupSession()
			So(err, ShouldBeNil)
			So(sess, ShouldNotBeNil)
		})
		Convey("with an invalid random source should work.", func() {
			ctrl := gomock.NewController(t)
			mock := NewMockReader(ctrl)

			mock.EXPECT().Read(gomock.Any()).Return(0, errors.New("some error"))

			sw := switchRandSource(mock)
			defer sw.Revert()

			sess, err := NewOutboundGroupSession()
			So(err, ShouldNotBeNil)
			So(sess, ShouldBeNil)
		})
	})
}

func TestOutboundGroupSessionClear(t *testing.T) {
	sess, _ := NewOutboundGroupSession()
	Convey("Clearing an OutboundGroupSession should not panic.", t, func() {
		So(func() {
			sess.Clear()
		}, ShouldNotPanic)
	})
}

func TestOutboundGroupSessionPickle(t *testing.T) {
	sess, _ := NewOutboundGroupSession()
	Convey("Pickleing an OutboundGroupSession", t, func() {
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

func TestOutboundGroupSessionUnpickle(t *testing.T) {
	_sess, _ := NewOutboundGroupSession()
	pickle, _ := _sess.Pickle("AA")

	Convey("Unpickleing an outbound group session", t, func() {
		Convey("with the correct key should work.", func() {
			sess, err := UnpickleOutboundGroupSession("AA", pickle)
			So(err, ShouldBeNil)
			So(sess, ShouldNotBeNil)
		})
		Convey("with an incorrect key should not work.", func() {
			sess, err := UnpickleOutboundGroupSession("invalid", pickle)
			So(err, ShouldNotBeNil)
			So(sess, ShouldBeNil)
		})
		Convey("with an empty key should not panic.", func() {
			So(func() {
				UnpickleOutboundGroupSession("", pickle)
			}, ShouldNotPanic)
		})
		Convey("with an empty pickle should not panic.", func() {
			So(func() {
				UnpickleOutboundGroupSession("AA", "")
			}, ShouldNotPanic)
		})
	})
}

func TestOutgoingGroupSessionID(t *testing.T) {
	sess, _ := NewOutboundGroupSession()
	Convey("Getting an ID from an OutgoingGroupSesison should work.", t, func() {
		id := sess.ID()
		So(id, ShouldNotBeEmpty)
	})
}

func TestOutgoingGroupSessionKey(t *testing.T) {
	sess, _ := NewOutboundGroupSession()
	Convey("Getting the key from an OutgoingGroupSesison should work.", t, func() {
		key := sess.Key()
		So(key, ShouldNotBeEmpty)
	})
}

func TestOutgoingGroupSessionMessageIndex(t *testing.T) {
	sess, _ := NewOutboundGroupSession()
	Convey("Getting the message index from an OutgoingGroupSesison should not panic.", t, func() {
		So(func() {
			sess.MessageIndex()
		}, ShouldNotPanic)
	})
}

func TestOutgoingGroupSessionEncrypt(t *testing.T) {
	sess, _ := NewOutboundGroupSession()

	Convey("Ecrypting", t, func() {
		Convey("a non-empty message should work.", func() {
			cipher, err := sess.Encrypt("plaintext")
			So(err, ShouldBeNil)
			So(cipher, ShouldNotBeEmpty)
		})
		Convey("an empty message should not panic.", func() {
			So(func() {
				sess.Encrypt("")
			}, ShouldNotPanic)
		})
	})
}
