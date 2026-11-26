//go:build linux

package wireguard

import (
	"errors"
	"fmt"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// defaultOpener runs the embedded wireguard-go.
func defaultOpener() DeviceOpener { return wireGuardOpener{} }

// wireGuardOpener creates wireguard-go devices on a kernel TUN interface.
type wireGuardOpener struct{}

// Open creates the TUN interface; wireguard-go brings the device up once
// the interface is set up.
func (wireGuardOpener) Open(name string, mtu int, log DeviceLog) (Device, error) {
	tunDevice, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create the TUN interface %s: %w", name, err)
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) { log.Verbose(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { log.Error(fmt.Sprintf(format, args...)) },
	}
	return &wireGuardDevice{dev: device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)}, nil
}

// wireGuardDevice adapts *device.Device to Device.
type wireGuardDevice struct {
	dev *device.Device
}

// IpcSet applies config. Its errors name only the UAPI error code: a parse
// error of wireguard-go quotes the line, which may hold a key.
func (d *wireGuardDevice) IpcSet(config string) error {
	err := d.dev.IpcSet(config)
	if err == nil {
		return nil
	}
	var ipcErr *device.IPCError
	if errors.As(err, &ipcErr) {
		return fmt.Errorf("the WireGuard device refused its configuration (UAPI error %d)", ipcErr.ErrorCode())
	}
	return errors.New("the WireGuard device refused its configuration")
}

func (d *wireGuardDevice) IpcGet() (string, error) { return d.dev.IpcGet() }

func (d *wireGuardDevice) SendKeepalive(peer Key) {
	if p := d.dev.LookupPeer(device.NoisePublicKey(peer)); p != nil {
		p.SendKeepalive()
	}
}

func (d *wireGuardDevice) Done() <-chan struct{} { return d.dev.Wait() }

func (d *wireGuardDevice) Close() { d.dev.Close() }
