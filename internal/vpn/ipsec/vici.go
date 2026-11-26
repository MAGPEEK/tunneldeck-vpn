package ipsec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// VICI is strongSwan's control protocol (src/libcharon/plugins/vici/
// README.md): length-prefixed packets over a stream socket. A packet is a
// type, for named types a name, and a message of nested sections,
// key-values and lists.

// Packet types.
const (
	packetCmdRequest      byte = 0 // named
	packetCmdResponse     byte = 1
	packetCmdUnknown      byte = 2
	packetEventRegister   byte = 3 // named
	packetEventUnregister byte = 4 // named
	packetEventConfirm    byte = 5
	packetEventUnknown    byte = 6
	packetEvent           byte = 7 // named
)

// Message element types.
const (
	elementSectionStart byte = 1
	elementSectionEnd   byte = 2
	elementKeyValue     byte = 3
	elementListStart    byte = 4
	elementListItem     byte = 5
	elementListEnd      byte = 6
)

// Protocol limits: names carry an 8-bit length, values a 16-bit one, and
// charon refuses packets above 512 KiB.
const (
	maxNameLength   = 255
	maxValueLength  = 65535
	maxPacketLength = 512 * 1024
)

var errMalformed = errors.New("malformed VICI message")

// entryKind is what a message entry holds.
type entryKind int

const (
	entryValue entryKind = iota
	entryList
	entrySection
)

// entry is one named element of a message.
type entry struct {
	key     string
	kind    entryKind
	value   string
	list    []string
	section *message
}

// message is a VICI message: entries in their wire order.
type message struct {
	entries []entry
}

func newMessage() *message { return &message{} }

// set adds the key-value key = value and returns m.
func (m *message) set(key, value string) *message {
	m.entries = append(m.entries, entry{key: key, kind: entryValue, value: value})
	return m
}

// setList adds the list key with values and returns m.
func (m *message) setList(key string, values ...string) *message {
	m.entries = append(m.entries, entry{key: key, kind: entryList, list: values})
	return m
}

// setSection adds the section key and returns it.
func (m *message) setSection(key string) *message {
	section := newMessage()
	m.entries = append(m.entries, entry{key: key, kind: entrySection, section: section})
	return section
}

// find returns the first entry named key of kind.
func (m *message) find(key string, kind entryKind) (entry, bool) {
	if m == nil {
		return entry{}, false
	}
	for _, e := range m.entries {
		if e.key == key && e.kind == kind {
			return e, true
		}
	}
	return entry{}, false
}

// get returns the value of key, "" when absent.
func (m *message) get(key string) string {
	e, _ := m.find(key, entryValue)
	return e.value
}

// getUint returns the value of key as a number, 0 when absent or invalid.
func (m *message) getUint(key string) uint64 {
	n, err := strconv.ParseUint(m.get(key), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// items returns the list key, nil when absent.
func (m *message) items(key string) []string {
	e, _ := m.find(key, entryList)
	return e.list
}

// section returns the section key, nil when absent.
func (m *message) section(key string) *message {
	e, _ := m.find(key, entrySection)
	return e.section
}

// sections returns the sections of m in order, with their names.
func (m *message) sections() []entry {
	if m == nil {
		return nil
	}
	var out []entry
	for _, e := range m.entries {
		if e.kind == entrySection {
			out = append(out, e)
		}
	}
	return out
}

// encode writes m in wire format.
func (m *message) encode(buf *bytes.Buffer) error {
	for _, e := range m.entries {
		if err := e.encode(buf); err != nil {
			return err
		}
	}
	return nil
}

func (e entry) encode(buf *bytes.Buffer) error {
	switch e.kind {
	case entryValue:
		if err := writeName(buf, elementKeyValue, e.key); err != nil {
			return err
		}
		return writeValue(buf, e.value)
	case entryList:
		if err := writeName(buf, elementListStart, e.key); err != nil {
			return err
		}
		for _, item := range e.list {
			buf.WriteByte(elementListItem)
			if err := writeValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(elementListEnd)
		return nil
	}
	if err := writeName(buf, elementSectionStart, e.key); err != nil {
		return err
	}
	if err := e.section.encode(buf); err != nil {
		return err
	}
	buf.WriteByte(elementSectionEnd)
	return nil
}

func writeName(buf *bytes.Buffer, element byte, name string) error {
	if name == "" || len(name) > maxNameLength {
		return fmt.Errorf("VICI name of %d bytes: %w", len(name), errMalformed)
	}
	buf.WriteByte(element)
	buf.WriteByte(byte(len(name)))
	buf.WriteString(name)
	return nil
}

func writeValue(buf *bytes.Buffer, value string) error {
	if len(value) > maxValueLength {
		return fmt.Errorf("VICI value of %d bytes: %w", len(value), errMalformed)
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	buf.Write(length[:])
	buf.WriteString(value)
	return nil
}

// decodeMessage reads a message in wire format.
func decodeMessage(data []byte) (*message, error) {
	d := decoder{data: data}
	m, err := d.message(0)
	if err != nil {
		return nil, err
	}
	if d.pos != len(d.data) {
		return nil, fmt.Errorf("section end at the top level: %w", errMalformed)
	}
	return m, nil
}

// maxDepth bounds the nesting of sections.
const maxDepth = 32

type decoder struct {
	data []byte
	pos  int
}

// message reads entries until the end of the data or of the section.
func (d *decoder) message(depth int) (*message, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("sections nested too deeply: %w", errMalformed)
	}
	m := newMessage()
	for d.pos < len(d.data) {
		element := d.data[d.pos]
		if element == elementSectionEnd {
			if depth > 0 {
				d.pos++
			}
			return m, nil
		}
		d.pos++
		if err := d.element(m, element, depth); err != nil {
			return nil, err
		}
	}
	if depth > 0 {
		return nil, fmt.Errorf("section not closed: %w", errMalformed)
	}
	return m, nil
}

func (d *decoder) element(m *message, element byte, depth int) error {
	name, err := d.name()
	if err != nil {
		return err
	}
	switch element {
	case elementKeyValue:
		value, err := d.value()
		if err != nil {
			return err
		}
		m.set(name, value)
	case elementListStart:
		items, err := d.list()
		if err != nil {
			return err
		}
		m.setList(name, items...)
	case elementSectionStart:
		section, err := d.message(depth + 1)
		if err != nil {
			return err
		}
		m.entries = append(m.entries, entry{key: name, kind: entrySection, section: section})
	default:
		return fmt.Errorf("element type %d: %w", element, errMalformed)
	}
	return nil
}

func (d *decoder) list() ([]string, error) {
	var items []string
	for d.pos < len(d.data) {
		element := d.data[d.pos]
		d.pos++
		switch element {
		case elementListEnd:
			return items, nil
		case elementListItem:
			item, err := d.value()
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		default:
			return nil, fmt.Errorf("element type %d in a list: %w", element, errMalformed)
		}
	}
	return nil, fmt.Errorf("list not closed: %w", errMalformed)
}

func (d *decoder) name() (string, error) {
	if d.pos >= len(d.data) {
		return "", fmt.Errorf("missing name: %w", errMalformed)
	}
	length := int(d.data[d.pos])
	d.pos++
	return d.take(length)
}

func (d *decoder) value() (string, error) {
	if d.pos+2 > len(d.data) {
		return "", fmt.Errorf("missing value length: %w", errMalformed)
	}
	length := int(binary.BigEndian.Uint16(d.data[d.pos:]))
	d.pos += 2
	return d.take(length)
}

func (d *decoder) take(n int) (string, error) {
	if d.pos+n > len(d.data) {
		return "", fmt.Errorf("truncated: %w", errMalformed)
	}
	s := string(d.data[d.pos : d.pos+n])
	d.pos += n
	return s, nil
}

// packet is one VICI packet. name is set for the named types.
type packet struct {
	kind    byte
	name    string
	message *message
}

func isNamed(kind byte) bool {
	return kind == packetCmdRequest || kind == packetEventRegister || kind == packetEventUnregister || kind == packetEvent
}

// writePacket sends p with its 32-bit big-endian length.
func writePacket(w io.Writer, p packet) error {
	var body bytes.Buffer
	body.WriteByte(p.kind)
	if isNamed(p.kind) {
		if len(p.name) > maxNameLength {
			return fmt.Errorf("VICI packet name of %d bytes: %w", len(p.name), errMalformed)
		}
		body.WriteByte(byte(len(p.name)))
		body.WriteString(p.name)
	}
	if p.message != nil {
		if err := p.message.encode(&body); err != nil {
			return err
		}
	}
	if body.Len() > maxPacketLength {
		return fmt.Errorf("VICI packet of %d bytes: %w", body.Len(), errMalformed)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(body.Len()))
	if _, err := w.Write(append(length[:], body.Bytes()...)); err != nil {
		return fmt.Errorf("send VICI packet: %w", err)
	}
	return nil
}

// readPacket receives one packet.
func readPacket(r io.Reader) (packet, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return packet{}, err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > maxPacketLength {
		return packet{}, fmt.Errorf("VICI packet of %d bytes: %w", size, errMalformed)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return packet{}, fmt.Errorf("read VICI packet: %w", err)
	}
	p := packet{kind: body[0]}
	rest := body[1:]
	if isNamed(p.kind) {
		if len(rest) == 0 || len(rest) < 1+int(rest[0]) {
			return packet{}, fmt.Errorf("VICI packet name: %w", errMalformed)
		}
		p.name, rest = string(rest[1:1+int(rest[0])]), rest[1+int(rest[0]):]
	}
	m, err := decodeMessage(rest)
	if err != nil {
		return packet{}, err
	}
	p.message = m
	return p, nil
}
