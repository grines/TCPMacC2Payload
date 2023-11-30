package osx

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"strings"
)

func UnsafeJXARemote(url string) string {

	// Fetch the data
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read the body as a string
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	bodyString := string(body)

	// Prepare the osascript command
	cmd := exec.Command("osascript", "-l", "JavaScript", "-e", bodyString)

	// Execute the command
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		panic(err)
	}

	// Output the result of the osascript command
	return out.String()
}

func UnsafeJXA(js string) string {
	// Executing the osascript command
	// Executing the osascript command
	cmd := exec.Command("osascript", "-l", "JavaScript", "-e", js)

	// Capture both standard output and standard error
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error executing script:", err)
		fmt.Println("Script output:", string(output))
		return "notta"
	}

	// Convert byte slice to string and trim any whitespace
	result := strings.TrimSpace(string(output))

	// Print the result
	fmt.Println("Script output:", result)
	return result
}
