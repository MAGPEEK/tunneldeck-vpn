package openvpn

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// managementMessage is one line received from the OpenVPN management
// interface (docs/openvpn-notes.md (c)).
type managementMessage interface{ managementMessage() }

// infoMessage is ">INFO:<text>", the banner sent on connect.
type infoMessage struct{ text string }

// holdMessage is ">HOLD:Waiting for hold release:<n>"; n is the pause in
// seconds OpenVPN would make on its own before the next attempt.
type holdMessage struct{ waitSeconds int }

// stateMessage is ">STATE:<ts>,<state>,<detail>,<tun ip>,<remote ip>,
// <remote port>,...". Missing trailing fields are empty.
type stateMessage struct {
	time       time.Time
	name       string
	detail     string
	tunnelIP   string
	remoteIP   string
	remotePort string
}

// byteCountMessage is ">BYTECOUNT:<in>,<out>": transport bytes since the
// process started.
type byteCountMessage struct{ in, out uint64 }

// logMessage is ">LOG:<ts>,<flags>,<text>".
type logMessage struct {
	time  time.Time
	flags string
	text  string
}

// passwordKind tells what a ">PASSWORD:" line is about.
type passwordKind int

const (
	// passwordOther covers notifications TunnelDeck does not use, such as
	// auth tokens; their content is never logged.
	passwordOther passwordKind = iota
	passwordNeeded
	passwordRejected
)

// passwordMessage is ">PASSWORD:Need '<realm>' ..." or ">PASSWORD:
// Verification Failed: '<realm>' ['<reason>']".
type passwordMessage struct {
	kind      passwordKind
	realm     string
	reason    string
	hasReason bool
}

// fatalMessage is ">FATAL:<text>", sent just before OpenVPN exits.
type fatalMessage struct{ text string }

// replyMessage is "SUCCESS: <text>" or "ERROR: <text>", the answer to the
// oldest pending command.
type replyMessage struct {
	success bool
	text    string
}

// ignoredMessage is any other line: real-time notifications TunnelDeck
// does not use and lines of multi-line replies.
type ignoredMessage struct{}

func (infoMessage) managementMessage()      {}
func (holdMessage) managementMessage()      {}
func (stateMessage) managementMessage()     {}
func (byteCountMessage) managementMessage() {}
func (logMessage) managementMessage()       {}
func (passwordMessage) managementMessage()  {}
func (fatalMessage) managementMessage()     {}
func (replyMessage) managementMessage()     {}
func (ignoredMessage) managementMessage()   {}

// Realms of ">PASSWORD:" prompts answered by TunnelDeck.
const (
	realmAuth       = "Auth"
	realmPrivateKey = "Private Key"
)

// realTimeParsers parse the payload after each known ">NAME:" prefix.
var realTimeParsers = map[string]func(string) (managementMessage, error){
	"INFO":      func(s string) (managementMessage, error) { return infoMessage{text: s}, nil },
	"HOLD":      parseHold,
	"STATE":     parseState,
	"BYTECOUNT": parseByteCount,
	"LOG":       parseLog,
	"PASSWORD":  parsePassword,
	"FATAL":     func(s string) (managementMessage, error) { return fatalMessage{text: s}, nil },
}

// parseManagementLine parses one line without its line ending. An error
// names the notification that was malformed but never repeats the line,
// which may hold secrets such as auth tokens.
func parseManagementLine(line string) (managementMessage, error) {
	if rest, ok := strings.CutPrefix(line, ">"); ok {
		name, payload, found := strings.Cut(rest, ":")
		parse, known := realTimeParsers[name]
		if !found || !known {
			return ignoredMessage{}, nil
		}
		msg, err := parse(payload)
		if err != nil {
			return nil, fmt.Errorf("malformed >%s notification: %w", name, err)
		}
		return msg, nil
	}
	if text, ok := strings.CutPrefix(line, "SUCCESS:"); ok {
		return replyMessage{success: true, text: strings.TrimSpace(text)}, nil
	}
	if text, ok := strings.CutPrefix(line, "ERROR:"); ok {
		return replyMessage{success: false, text: strings.TrimSpace(text)}, nil
	}
	return ignoredMessage{}, nil
}

func parseHold(payload string) (managementMessage, error) {
	index := strings.LastIndexByte(payload, ':')
	if index < 0 {
		return holdMessage{}, nil
	}
	seconds, err := strconv.Atoi(payload[index+1:])
	if err != nil || seconds < 0 {
		return nil, errors.New("hold time is not a number of seconds")
	}
	return holdMessage{waitSeconds: seconds}, nil
}

func parseState(payload string) (managementMessage, error) {
	fields := strings.Split(payload, ",")
	if len(fields) < 2 || fields[1] == "" {
		return nil, errors.New("state name missing")
	}
	at, err := parseUnixTime(fields[0])
	if err != nil {
		return nil, err
	}
	field := func(i int) string {
		if i < len(fields) {
			return fields[i]
		}
		return ""
	}
	return stateMessage{
		time:       at,
		name:       fields[1],
		detail:     field(2),
		tunnelIP:   field(3),
		remoteIP:   field(4),
		remotePort: field(5),
	}, nil
}

func parseByteCount(payload string) (managementMessage, error) {
	in, out, found := strings.Cut(payload, ",")
	if !found {
		return nil, errors.New("expected two counters")
	}
	bytesIn, errIn := strconv.ParseUint(in, 10, 64)
	bytesOut, errOut := strconv.ParseUint(out, 10, 64)
	if errIn != nil || errOut != nil {
		return nil, errors.New("counters are not numbers")
	}
	return byteCountMessage{in: bytesIn, out: bytesOut}, nil
}

// parseLog splits only on the first two commas: the text contains commas.
func parseLog(payload string) (managementMessage, error) {
	fields := strings.SplitN(payload, ",", 3)
	if len(fields) < 3 {
		return nil, errors.New("expected time, flags and text")
	}
	at, err := parseUnixTime(fields[0])
	if err != nil {
		return nil, err
	}
	return logMessage{time: at, flags: fields[1], text: fields[2]}, nil
}

func parsePassword(payload string) (managementMessage, error) {
	if rest, ok := strings.CutPrefix(payload, "Need '"); ok {
		realm, _, found := strings.Cut(rest, "'")
		if !found {
			return nil, errors.New("unterminated realm")
		}
		return passwordMessage{kind: passwordNeeded, realm: realm}, nil
	}
	if rest, ok := strings.CutPrefix(payload, "Verification Failed: '"); ok {
		realm, tail, found := strings.Cut(rest, "'")
		if !found {
			return nil, errors.New("unterminated realm")
		}
		reason, hasReason := rejectionReason(tail)
		return passwordMessage{kind: passwordRejected, realm: realm, reason: reason, hasReason: hasReason}, nil
	}
	return passwordMessage{kind: passwordOther}, nil
}

// rejectionReason extracts <reason> from " ['<reason>']".
func rejectionReason(tail string) (string, bool) {
	tail = strings.TrimSpace(tail)
	inner, ok := strings.CutPrefix(tail, "['")
	if !ok {
		return "", false
	}
	inner, ok = strings.CutSuffix(inner, "']")
	if !ok {
		return "", false
	}
	return inner, true
}

func parseUnixTime(field string) (time.Time, error) {
	seconds, err := strconv.ParseInt(field, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("timestamp is not a number")
	}
	return time.Unix(seconds, 0).UTC(), nil
}

// Management commands sent by the driver. "state on" and "log on" without
// "all" avoid history blocks; nothing has happened while OpenVPN is held.
const (
	commandStateOn     = "state on"
	commandLogOn       = "log on"
	commandByteCount   = "bytecount 2" // a >BYTECOUNT: line every 2 seconds
	commandHoldRelease = "hold release"
	commandSignalTerm  = "signal SIGTERM"
)

// credentialCommand renders `<command> "<realm>" "<value>"` with the
// escaping OpenVPN's parser expects inside double quotes: backslash and
// double quote are escaped, everything else is sent as it is. The values
// were validated by Render (at most 255 bytes, no control characters).
func credentialCommand(command, realm, value string) string {
	return fmt.Sprintf(`%s "%s" "%s"`, command, escapeQuoted(realm), escapeQuoted(value))
}

func escapeQuoted(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}
