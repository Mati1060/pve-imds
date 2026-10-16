// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderMultiplePlaceholders(t *testing.T) {
	tmpl := "a: {{ secret \"one\" }}\nb: {{secret \"two\"}}\nc: {{   secret   \"one\"   }}\n"
	out, err := Render(tmpl, map[string]string{"one": "1", "two": "2"})
	require.NoError(t, err)
	assert.Equal(t, "a: 1\nb: 2\nc: 1\n", out)
}

func TestRenderMultiline(t *testing.T) {
	out, err := Render("k: {{\n  secret \"x\"\n}}", map[string]string{"x": "v"})
	require.NoError(t, err)
	assert.Equal(t, "k: v", out)
}

func TestRenderMissingField(t *testing.T) {
	out, err := Render("{{ secret \"a\" }} {{ secret \"b\" }} {{ secret \"c\" }}", map[string]string{"b": "x"})
	require.ErrorIs(t, err, ErrMissingField)
	assert.Contains(t, err.Error(), "a, c")
	assert.Empty(t, out, "no partial output on error")
}

func TestRenderUnknownSyntaxUntouched(t *testing.T) {
	tmpl := "{{ .Values.x }} {{ secret x }} {{ secret 'x' }} {{ secrets \"x\" }} " +
		"{{ secret \"x\" | b64 }} {% raw %} ${x} {{ ds.meta_data.name }}"
	out, err := Render(tmpl, map[string]string{"x": "SECRET"})
	require.NoError(t, err)
	assert.Equal(t, tmpl, out)
}

func TestRenderNoPlaceholders(t *testing.T) {
	out, err := Render("plain: text\n---\nkind: x\n", nil)
	require.NoError(t, err)
	assert.Equal(t, "plain: text\n---\nkind: x\n", out)
}

func TestRenderNoReexpansion(t *testing.T) {
	out, err := Render("{{ secret \"a\" }}", map[string]string{"a": "{{ secret \"b\" }}", "b": "nope"})
	require.NoError(t, err)
	assert.Equal(t, "{{ secret \"b\" }}", out)
}

func TestRenderSpecialCharacters(t *testing.T) {
	out, err := Render("x: {{ secret \"v\" }}", map[string]string{"v": "$1 \\n ${x} & <-->"})
	require.NoError(t, err)
	assert.Equal(t, "x: $1 \\n ${x} & <-->", out)
}
