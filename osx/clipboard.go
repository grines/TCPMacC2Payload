package osx

import (
	"time"
)

func Clipboard() string {
	result := runCommandClipboard()
	return result
}

func ClipboardMonitor(newEntries chan<- string, stop <-chan string) {
	var lastSeen string

	for {
		select {
		case <-stop:
			return
		default:
			currentClipboard := runCommandClipboard()
			if currentClipboard != lastSeen && currentClipboard != "" {
				select {
				case newEntries <- currentClipboard:
					lastSeen = currentClipboard
				default:
					// Do nothing if newEntries is not ready to receive
				}
			}
			time.Sleep(10 * time.Second)
		}
	}
}
