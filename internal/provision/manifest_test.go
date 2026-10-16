// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package provision

const (
	talosPrefix = "https://pxe.factory.talos.dev/pxe/"
	talosURL    = talosPrefix + "376567988ad370138ad8b2698212367b8edcb69b5fd68c80be1f2ec7d603b4ba/v1.14.2/nocloud-amd64-secureboot"
	sha         = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
)

var allowed = []string{talosPrefix}
