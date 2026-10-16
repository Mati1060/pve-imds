// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package pxestate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/config"
)

func TestFromConfig(t *testing.T) {
	conn := config.SecretsConfig{Address: "https://bao:8200", TokenFile: "/run/token"}
	enabled := config.PXEConfig{Enabled: true, StatePathTemplate: DefaultPathTemplate}

	s, err := FromConfig(config.PXEConfig{Enabled: false}, config.SecretsConfig{})
	require.NoError(t, err)
	assert.Nil(t, s, "disabled needs no connection settings")

	// Templating (secrets.enabled) is off; the store still works.
	s, err = FromConfig(enabled, conn)
	require.NoError(t, err)
	assert.NotNil(t, s)

	noAddr := conn
	noAddr.Address = ""
	_, err = FromConfig(enabled, noAddr)
	require.ErrorContains(t, err, "secrets.address")

	noToken := conn
	noToken.TokenFile = ""
	_, err = FromConfig(enabled, noToken)
	require.ErrorContains(t, err, "secrets.token_file")

	badTmpl := enabled
	badTmpl.StatePathTemplate = "kv/data/pve-imds/pxe"
	_, err = FromConfig(badTmpl, conn)
	require.ErrorContains(t, err, "{uuid}")
}
