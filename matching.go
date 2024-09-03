package main

import (
	"math"
	"regexp"
	"unicode/utf8"
)

// Min Definitions.
var MinimumCharacters = math.Pow(2, 4)                   // Minimum password length.
var MinimumNumbersPercentage float32 = 5                 // Minimum numbers as percentage of password length.
var MinimumSpecialsPercentage float32 = 5                // Minimum special characters as percentage of password length.
var MinimumUppercasePercentage float32 = 5               // Minimum uppercase latin characters as percentage of password length.
var MinimumLowercasePercentage float32 = 5               // Minimum lowercase latin characters as percentage of password length.
var MinimumUsernamePasswordDistanceLengthPercentage = 75 // Minimum levinshtein distance based on percentage of password length.

// Regex Definition.
var AllowedCharacters = regexp.MustCompile(`[\n]`)         // Match characters that are not allowed.
var SpecialCharacters = regexp.MustCompile(`[^A-Za-z0-9]`) // Match special characters such as "&".
var NumberCharacters = regexp.MustCompile(`[0-9]`)         // Match numbers.
var LowercaseCharacters = regexp.MustCompile(`[a-z]`)      // Match lowercase latin characters.
var UppercaseCharacters = regexp.MustCompile(`[A-Z]`)      // Match uppercase latin characters.

// Returns regexp match count.
func CharacterCount(string1 string, regex *regexp.Regexp) int {
	matches := regex.FindAll([]byte(string1), -1)

	return len(matches)
}

// Levinstein distance function.
func Distance(string1, string2 string) int {
	// Check if either strings are empty.
	if len(string1) == 0 {
		return utf8.RuneCountInString(string2)
	}
	if len(string2) == 0 {
		return utf8.RuneCountInString(string1)
	}

	// Check if strings are the same.
	if string1 == string2 {
		return 0
	}

	// Convert strings to rune slices for character counting.
	s1Rune := []rune(string1)
	s2Rune := []rune(string2)

	// Swap if length is 1 is greater than 2.
	if len(s1Rune) > len(s2Rune) {
		s1Rune, s2Rune = s2Rune, s1Rune
	}
	lenS1 := len(s1Rune)
	lenS2 := len(string2)

	// Create character row.
	var x []uint16
	if lenS1+1 > 2^5 {
		x = make([]uint16, lenS1+1)
	} else {
		x = make([]uint16, 2^5)
		x = x[:lenS1+1]
	}

	for i := 1; i < len(x); i++ {
		x[i] = uint16(i)
	}

	_ = x[lenS1]
	for i := 1; i <= lenS2; i++ {
		prev := uint16(i)
		for j := 1; j <= lenS1; j++ {
			current := x[j-1]
			if s2Rune[i-1] != s1Rune[j-1] {
				current = min(min(x[j-1]+1, prev+1), x[j]+1)
			}
			x[j-1] = prev
			prev = current
		}
		x[lenS1] = prev
	}

	return int(x[lenS1])
}

func min(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}
