// LocalAuthentication.framework bridge.
//
// Implementing this in Objective-C rather than Zig avoids hand-rolling
// objc_msgSend, NSString construction, and the Block ABI.
// Two C-ABI exports are sufficient for our use cases (Touch ID-gated
// keychain unlock and MCP `get_secret`).
//
// Build flag in build.zig: -fobjc-arc + -framework LocalAuthentication.

#import <LocalAuthentication/LocalAuthentication.h>
#include <dispatch/dispatch.h>

// Returns 1 if biometrics (Touch ID / Face ID) are available and enrolled,
// else 0.
int secretctl_la_available(void) {
    LAContext *ctx = [[LAContext alloc] init];
    NSError *err = nil;
    BOOL ok = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                               error:&err];
    return ok ? 1 : 0;
}

// Synchronously evaluate biometric policy.
// Returns:
//   1  on user-authenticated success
//   0  on cancel / failure / not-available
//
// `reason` is the localized message shown in the system prompt.
int secretctl_la_evaluate(const char *reason) {
    LAContext *ctx = [[LAContext alloc] init];
    NSError *err = nil;
    if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                          error:&err]) {
        return 0;
    }

    NSString *r = [NSString stringWithUTF8String:reason];
    __block BOOL result = NO;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
        localizedReason:r
                  reply:^(BOOL success, NSError * _Nullable error) {
                      (void)error;
                      result = success;
                      dispatch_semaphore_signal(sem);
                  }];

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    return result ? 1 : 0;
}
