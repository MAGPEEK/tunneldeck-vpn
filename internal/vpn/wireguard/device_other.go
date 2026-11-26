//go:build !linux

package wireguard

import "errors"

// defaultOpener refuses: the embedded wireguard-go runs on Linux only.
func defaultOpener() DeviceOpener { return unsupportedOpener{} }

type unsupportedOpener struct{}

func (unsupportedOpener) Open(string, int, DeviceLog) (Device, error) {
	return nil, errors.New("WireGuard tunnels need Linux")
}
