package secrets

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// placeholderRe matches {{ secret "field" }} with optional whitespace inside
// the braces. Anything else, including other {{ ... }} expressions, is left
// untouched.
var placeholderRe = regexp.MustCompile(`\{\{\s*secret\s+"([^"\\\n]+)"\s*\}\}`)

// Render replaces every {{ secret "field" }} placeholder in tmpl with the
// matching value from values. Substitution is a single pass: placeholders
// that appear inside substituted values are not expanded.
//
// If any referenced field is missing, Render returns an error wrapping
// ErrMissingField that names the missing fields, and no output.
func Render(tmpl string, values map[string]string) (string, error) {
	missing := map[string]struct{}{}
	out := placeholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		field := placeholderRe.FindStringSubmatch(m)[1]
		v, ok := values[field]
		if !ok {
			missing[field] = struct{}{}
			return m
		}
		return v
	})

	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for f := range missing {
			names = append(names, f)
		}
		sort.Strings(names)
		return "", fmt.Errorf("%w: %s", ErrMissingField, strings.Join(names, ", "))
	}
	return out, nil
}
