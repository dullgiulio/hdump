package main

// https://github.com/golang/go/wiki/heapdump14

import (
	"time"
    "bytes"
	"encoding/binary"
	"errors"
	"io"
)

type fieldKind int
type tag int

type field struct {
	kind fieldKind
	ptr  uint64
}

var header = []byte("go1.4 heap dump\n")

const (
	fieldKindEol   fieldKind = 0
	fieldKindPtr             = 1
	fieldKindIface           = 2
	fieldKindEface           = 3
)

const (
	tagEOF             tag = 0
	tagObject              = 1
	tagOtherRoot           = 2
	tagType                = 3
	tagGoroutine           = 4
	tagStackFrame          = 5
	tagParams              = 6
	tagFinalizer           = 7
	tagItab                = 8
	tagOSThread            = 9
	tagMemStats            = 10
	tagQueuedFinalizer     = 11
	tagData                = 12
	tagBSS                 = 13
	tagDefer               = 14
	tagPanic               = 15
	tagMemProf             = 16
	tagAllocSample         = 17
)

func readHeader(r io.ByteReader) error {
	head := make([]byte, len(header))
	if _, err := io.ReadFull(io.Reader(r), head); err != nil {
		return nil
	}
	if bytes.Compare(header, head) != 0 {
		return errors.New("invalid heapdump")
	}
	return nil
}

func readString(r io.ByteReader) (string, error) {
	nbytes, err := binary.ReadUvarint(r)
	if err != nil {
		return "", err
	}
	buf := make([]byte, nbytes)
	_, err = io.ReadFull(io.Reader(r), buf)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func readFieldlist(r io.ByteReader) ([]field, error) {
	fields := make([]field, 0)
	for {
		t, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, err
		}
		if fieldKind(t) == fieldKindEol {
			return fields, nil
		}
		v, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field{fieldKind(t), v})
	}
}

type object struct {
	addr     uint64
	contents string
	fields   []field
}

func readObject(r io.ByteReader) (*object, error) {
	addr, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	contents, err := readString(r)
	if err != nil {
		return nil, err
	}
	fields, err := readFieldlist(r)
	if err != nil {
		return nil, err
	}
	return &object{addr, contents, fields}, nil
}

type root struct {
	descr string
	ptr   uint64
}

func readOtherRoot(r io.ByteReader) (*root, error) {
	descr, err := readString(r)
	if err != nil {
		return nil, err
	}
	ptr, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	return &root{descr, ptr}, nil
}

type Type struct {
	addr  uint64
	size  uint64
	name  string
	isPtr bool
}

func readType(r io.ByteReader) (*Type, error) {
	addr, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	size, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	name, err := readString(r)
	if err != nil {
		return nil, err
	}
	isptr, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	return &Type{addr, size, name, isptr != 0}, nil
}

type status int

const (
	statusIdle     status = 0
	statusRunnable        = 1
	statusSyscall         = 2
	statusWaiting         = 3
)

type Goroutine struct {
	addr         uint64
	rframe       uint64
	id           uint64
	stmt         uint64
	status       status
	isSys        bool
	isBackground bool
	started      time.Time
	waitReason   string
	ctx          uint64
	MThread      uint64
	dfer         uint64
	pnic         uint64
}

func readGoroutine(r io.ByteReader) (*Goroutine, error) {
	var err error
	g := &Goroutine{}
	g.addr, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	g.rframe, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	g.id, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	g.stmt, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	st, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	g.status = status(st)
	b, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	g.isSys = b != 1
	b, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	g.isBackground = b != 1
	started, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	g.started = time.Unix(started/time.Second, started%time.Second)
	g.waitReason, err = readString(r)
	if err != nil {
		return nil, err
	}
	g.ctx, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	g.MThread, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	g.dfer, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	g.pnic, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	return g, nil
}

type stackFrame struct {
	ptr        uint64
	depth      uint64
	childPtr   uint64
	content    string
	startPC    uint64
	currentPC  uint64
	continuePC uint64
	name       string
	fields     []field
}

func readStackFrame(r io.ByteReader) (*stackFrame, error) {
	var err error
	s := &stackFrame{}
	s.ptr, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	s.depth, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	s.childPtr, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	s.content, err = readString(r)
	if err != nil {
		return nil, err
	}
	s.startPC, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	s.currentPC, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	s.continuePC, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	s.name, err = readString(r)
	if err != nil {
		return nil, err
	}
	s.fields, err = readFieldlist(r)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// dump params
// finalizer
// itab
// osthread
// memstats
// queuedfinalizer
// data
// bss
// defer
// panic
// alloc/free profile record
// alloc sample record
