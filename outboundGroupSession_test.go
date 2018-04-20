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
