package golm

import (
	"crypto/rand"
	"io"
	"sync"
)

var sw *randsourceSwitcher

type randsourceSwitcher struct {
	orig  io.Reader
	mutex sync.Mutex
}

func guardRandSource() *randsourceSwitcher {
	if sw == nil {
		sw = &randsourceSwitcher{}
	}
	return sw.Guard()
}

func switchRandSource(newSource io.Reader) *randsourceSwitcher {
	if sw == nil {
		sw = &randsourceSwitcher{}
	}
	return sw.Switch(newSource)
}

func (sw *randsourceSwitcher) Guard() *randsourceSwitcher {
	sw.mutex.Lock()
	return sw
}

func (sw *randsourceSwitcher) Free() *randsourceSwitcher {
	sw.mutex.Unlock()
	return sw
}

func (sw *randsourceSwitcher) Switch(newSource io.Reader) *randsourceSwitcher {
	sw.mutex.Lock()
	sw.orig = rand.Reader
	rand.Reader = newSource
	return sw
}

func (sw *randsourceSwitcher) Revert() *randsourceSwitcher {
	rand.Reader = sw.orig
	sw.mutex.Unlock()
	return sw
}
