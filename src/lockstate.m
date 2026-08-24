// Screen-lock state, for deciding which authorization method to demand.
//
// Touch ID needs a finger on the sensor, so it is only a usable authorization
// method when someone is actually at the machine. When the screen is locked we
// have to fall back to an out-of-band approval (see docs/2fa-design.md).
// Detecting which situation we are in is what this file does.
//
// CGSessionCopyCurrentDictionary works from an ordinary CLI: no entitlement,
// no TCC prompt, no window-server connection of our own. Measured on
// macOS 25.5: while unlocked the CGSSessionScreenIsLocked key is *absent*
// rather than present-and-false, so "absent" must read as unlocked.
//
// Build flags in build.zig: -fobjc-arc + -framework CoreGraphics.

#import <Foundation/Foundation.h>

extern CFDictionaryRef CGSessionCopyCurrentDictionary(void);

// 1  = screen is locked
// 0  = screen is not locked
// -1 = cannot tell (no GUI session at all: ssh-only login, launchd context)
int secretctl_screen_is_locked(void) {
    CFDictionaryRef d = CGSessionCopyCurrentDictionary();
    if (!d) return -1;
    NSDictionary *s = (__bridge NSDictionary *)d;

    id locked = s[@"CGSSessionScreenIsLocked"];
    // A session with no console at all (fast-user-switched away, or a
    // non-GUI session) is not "unlocked" in any useful sense either.
    id onConsole = s[@"kCGSSessionOnConsoleKey"];

    int result;
    if (locked != nil && [locked boolValue]) {
        result = 1;
    } else if (onConsole != nil && ![onConsole boolValue]) {
        result = 1;
    } else if (locked == nil && onConsole == nil) {
        result = -1;
    } else {
        result = 0;
    }

    CFRelease(d);
    return result;
}
