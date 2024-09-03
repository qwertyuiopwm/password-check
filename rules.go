package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type Rule struct {
	Name func(username, password string) string
	Test func(username, password string) bool
}

var RockyouDownload = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

func DownloadRockyou() (*os.File, error) {
	info("Downloading rockyou.txt")
	file, err := os.Create("rockyou.txt")
	if err != nil {
		return nil, err
	}

	res, err := http.Get(RockyouDownload)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	_, err = io.Copy(file, res.Body)
	if err != nil {
		return nil, err
	}

	return file, nil
}

func ConstantString(str string) func(_, _ string) string {
	return func(_, _ string) string { return str }
}

var Rules = []Rule{
	// Password != Username.
	{
		Name: ConstantString("Password cannot be the same as the username"),
		Test: func(username, password string) bool {
			return username != password
		},
	},
	// Leveinstein > len*MinDistancePercentage.
	{
		Name: ConstantString("Password cannot be similar to the username."),
		Test: func(username, password string) bool {
			var DistanceResult = Distance(username, password)
			var MinDistance = float32(len(password)) * (float32(MinimumUsernamePasswordDistanceLengthPercentage) / 100.0)

			return DistanceResult > int(MinDistance)
		},
	},
	// Password cannot contain username.
	{
		Name: ConstantString("Password cannot contain the username."),
		Test: func(username, password string) bool {
			matched, _ := regexp.MatchString(strings.ToLower(username), strings.ToLower(password))
			return !matched
		},
	},
	// Username cannot contain password.
	{
		Name: ConstantString("Username cannot contain the password."),
		Test: func(username, password string) bool {
			matched, _ := regexp.MatchString(strings.ToLower(password), strings.ToLower(username))
			return !matched
		},
	},
	// Password must not contain banned characters.
	{
		Name: func(username, password string) string {
			var uniqueCharacters = map[string]bool{}
			matches := AllowedCharacters.FindAllString(password, -1)
			for _, value := range matches {
				uniqueCharacters[value] = true
			}

			keys := make([]string, 0, len(uniqueCharacters))
			for k := range uniqueCharacters {
				keys = append(keys, k)
			}

			return fmt.Sprintf("Password cannot contain the characters %s", strings.Join(keys, ","))
		},
		Test: func(username, password string) bool {
			return !AllowedCharacters.MatchString(password)
		},
	},
	// Password must be longer than or the same as defined minimum.
	{
		Name: ConstantString(fmt.Sprintf("Password must be at least %d characters long", int(MinimumCharacters))),
		Test: func(_, password string) bool {
			return float64(len(password)) >= MinimumCharacters
		},
	},
	// Password must have be a defined minimum percentage of numbers.
	{
		Name: func(_, password string) string {
			var passwordLength = float64(len(password))
			var minChars = math.Ceil(passwordLength * float64((MinimumNumbersPercentage / 100.0)))

			return fmt.Sprintf("Password must have atleast %d numbers! (%d%s of password length)", int(minChars), int(MinimumNumbersPercentage), "%")
		},
		Test: func(username, password string) bool {
			var passwordLength = float64(len(password))
			var minChars = math.Ceil(passwordLength * float64((MinimumNumbersPercentage / 100.0)))

			return CharacterCount(password, NumberCharacters) >= int(minChars)
		},
	},
	// Password must have be a defined minimum percentage of special characters.
	{
		Name: func(_, password string) string {
			var passwordLength = float64(len(password))
			var minChars = math.Ceil(passwordLength * float64((MinimumSpecialsPercentage / 100.0)))

			return fmt.Sprintf("Password must have atleast %d special characters! (%d%s of password length)", int(minChars), int(MinimumNumbersPercentage), "%")
		},
		Test: func(username, password string) bool {
			var passwordLength = float64(len(password))
			var minChars = math.Ceil(passwordLength * float64((MinimumNumbersPercentage / 100.0)))

			return CharacterCount(password, SpecialCharacters) >= int(minChars)
		},
	},
	// Password must have be a defined minimum percentage of uppercase letters.
	{
		Name: func(_, password string) string {
			var passwordLength = float64(len(password))
			var minChars = math.Ceil(passwordLength * float64((MinimumUppercasePercentage / 100.0)))

			return fmt.Sprintf("Password must have atleast %d uppercase letters! (%d%s of password length)", int(minChars), int(MinimumNumbersPercentage), "%")
		},
		Test: func(username, password string) bool {
			var passwordLength = float64(len(password))
			var minChars = math.Ceil(passwordLength * float64((MinimumNumbersPercentage / 100.0)))

			return CharacterCount(password, UppercaseCharacters) >= int(minChars)
		},
	},
	// Password must have be a defined minimum percentage of lowercase letters.
	{
		Name: func(_, password string) string {
			var passwordLength = float64(len(password))
			var minChars = math.Ceil(passwordLength * float64((MinimumLowercasePercentage / 100.0)))

			return fmt.Sprintf("Password must have atleast %d lowercase letters! (%d%s of password length)", int(minChars), int(MinimumNumbersPercentage), "%")
		},
		Test: func(username, password string) bool {
			var passwordLength = float64(len(password))
			var minChars = math.Ceil(passwordLength * float64((MinimumNumbersPercentage / 100.0)))

			return CharacterCount(password, LowercaseCharacters) >= int(minChars)
		},
	},
	// Password cannot be found in the rockyou.txt file.
	{
		Name: ConstantString("Password cannot be found within the rockyou.txt file."),
		Test: func(username, password string) bool {
			var found = false

			file, err := os.OpenFile("rockyou.txt", os.O_RDONLY, os.ModePerm)
			if os.IsNotExist(err) {
				file, err = DownloadRockyou()
			}
			if err != nil {
				fmt.Printf("Failed to read rockyou.txt %v\n", err)
				return false
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)

			for scanner.Scan() {
				if strings.TrimSpace(scanner.Text()) == password {
					found = true
					break
				}
			}

			return !found
		},
	},
}
