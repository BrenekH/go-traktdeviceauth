package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/BrenekH/go-traktdeviceauth"
)

func main() {
	clientID := input("Please enter your app's client id: ")
	clientSecret := input("Please enter your app's client secret: ")

	cR, err := traktdeviceauth.GenerateNewCode(clientID)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Please visit %s and enter the following code: %s\n", cR.VerificationURL, cR.UserCode)

	tR, err := traktdeviceauth.PollForAuthToken(cR, clientID, clientSecret)
	if err != nil {
		panic(err)
	}

	fmt.Printf("AccessToken: %s\nRefreshToken: %s\nExpires at: %s", tR.AccessToken, tR.RefreshToken, tR.ExpiresAt.String())
}

// input mimics Python's input function, which outputs a prompt and
// takes bytes from stdin until a newline and returns a string.
func input(prompt string) string {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if ok := scanner.Scan(); ok {
		return scanner.Text()
	}
	return ""
}
