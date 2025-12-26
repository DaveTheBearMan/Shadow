package main

import (
	"fmt"
	"os/exec"
)

func runCommand(command string) (response string) {
	fmt.Printf("! %s\n", command)
	output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("ERROR: %s", err)
	}
	return string(output)
}
