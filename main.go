package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	var reader = bufio.NewReader(os.Stdin)

	for {
		var PassedTests = len(Rules)
		fmt.Print("Username: ")
		username, _ := reader.ReadString('\n')
		fmt.Print("Password: ")
		password, _ := reader.ReadString('\n')
		fmt.Println("")

		username = strings.TrimSpace(username)
		password = strings.TrimSpace(password)

		for _, rule := range Rules {
			if !rule.Test(username, password) {
				warn(fmt.Sprintf("Test Failed: %s", rule.Name(username, password)))
				PassedTests -= 1
				continue
			}
			ok(fmt.Sprintf("Test Passed: %s", rule.Name(username, password)))
		}
		if PassedTests <= 0 {
			fmt.Println("Your password-username combination failed!")
		}
		fmt.Printf("Total passed tests: %d/%d\n\n", PassedTests, len(Rules))
	}
}
