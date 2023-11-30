package osx

/*
#cgo CFLAGS: -g -Wall -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework OSAKit -framework Foundation -framework AppleScriptObjC
#import "jxaScriptBridge.h"
#import <Cocoa/Cocoa.h>
*/
import "C"

func RunOSA(jxaScript string) {
	// Call the Objective-C function
	cstr := C.CString(jxaScript)
	C.RunJXA(cstr)
}

func RunOSAURL(jxaScript string) {
	// Call the Objective-C function
	cstr := C.CString(jxaScript)
	C.RunJXAUrl(cstr)
}
