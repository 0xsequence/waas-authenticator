package textcase

import (
	"bytes"
	"unicode"
	"unicode/utf8"
)

// Converts input string to "kebab-case" naming convention.
// Removes all whitespace and special characters. Supports Unicode characters.
func KebabCase(input string) string {
	str := markLetterCaseChanges(input)

	var b bytes.Buffer

	state := idle
	for i := 0; i < len(str); {
		r, size := utf8.DecodeRuneInString(str[i:])
		i += size
		state = state.next(r)
		switch state {
		case firstAlphaNum, alphaNum:
			b.WriteRune(unicode.ToLower(r))
		case delimiter:
			b.WriteByte('-')
		}
	}
	if (state == idle || state == delimiter) && b.Len() > 0 {
		b.Truncate(b.Len() - 1)
	}

	return b.String()
}
