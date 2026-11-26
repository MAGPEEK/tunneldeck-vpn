// Package ipsec is the IPsec/IKEv2 driver (SPEC §19): strongSwan's charon
// with the kernel-libipsec plugin as a child process, driven over its VICI
// socket. ESP runs in user space on the tunnel device, so the host gets no
// XFRM policies; the profile form, validation and advisories follow the
// standards of SPEC §19.1. It is the only package that knows IPsec.
package ipsec
