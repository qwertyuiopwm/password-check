package main

import "fmt"

func warn(str string) {
	fmt.Printf("\033[91m\u2717\033[39m | %s\n", str)
}

func ok(str string) {
	fmt.Printf("\033[92m\u2713\033[39m | %s\n", str)
}

func info(str string) {
	fmt.Printf("\033[93m\u2712\033[39m | %s\n", str)
}
