#import "jxaScriptBridge.h"
#import <Foundation/Foundation.h>
#import <OSAKit/OSAKit.h>


// Function to be called from Go
const char* RunJXA(const char* s) {
        NSString *codeString = [NSString stringWithUTF8String:s];
	NSError *err = nil;
    OSALanguage *lang = [OSALanguage languageForName:@"JavaScript"];
    OSAScript *script = [[OSAScript alloc] initWithSource:codeString language:lang];
	NSDictionary *dict = nil;
    NSAppleEventDescriptor *res = [script executeAndReturnError:&dict];
	if ([dict count] > 0) {
        NSString *result = dict[@"OSAScriptErrorMessageKey"];
        return [result UTF8String];
    }
    NSString* fmtString = [NSString stringWithFormat:@"%@", res];
    const char *output = [fmtString UTF8String];
    return output;
}

// Function to be called from Go
const char* RunJXAUrl(const char* s) {
    NSString *codeString = [NSString stringWithUTF8String:s];
	NSError *err = nil;
	NSURL * urlToRequest = [NSURL URLWithString:codeString];
	if(urlToRequest)
	{
		codeString = [NSString stringWithContentsOfURL: urlToRequest
										encoding:NSUTF8StringEncoding error:&err];
	}
	if(!err){
		NSLog(@"Script Contents::%@",codeString);
	}
    OSALanguage *lang = [OSALanguage languageForName:@"JavaScript"];
    OSAScript *script = [[OSAScript alloc] initWithSource:codeString language:lang];
	NSDictionary *dict = nil;
    NSAppleEventDescriptor *res = [script executeAndReturnError:&dict];
	if ([dict count] > 0) {
        NSString *result = dict[@"OSAScriptErrorMessageKey"];
        return [result UTF8String];
    }
    NSString* fmtString = [NSString stringWithFormat:@"%@", res];
    const char *output = [fmtString UTF8String];
    return output;
}