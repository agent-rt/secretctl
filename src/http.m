// HTTPS via NSURLSession.
//
// Not std.http.Client: the standard library's HTTP and TLS surface has changed
// shape across recent Zig releases, and this project already carries the ObjC
// bridge pattern (local_auth.m, lockstate.m) with dispatch_semaphore to make an
// async API synchronous. It also keeps request bodies out of argv, which
// shelling out to curl would not — the bodies here are signed approval
// requests, and `ps` is readable by any process on the machine.
//
// Build flags in build.zig: -fobjc-arc + -framework Foundation.

#import <Foundation/Foundation.h>
#include <string.h>

// Return codes. Negative means the request never completed, so the caller can
// tell "the network failed" from "the service said no", which are different
// things when the answer gates a secret.
#define SC_HTTP_OK             0
#define SC_HTTP_BAD_ARGS      -1
#define SC_HTTP_TRANSPORT     -2
#define SC_HTTP_TIMEOUT       -3
#define SC_HTTP_BODY_TOO_BIG  -4

/// Perform one request and block until it finishes.
///
/// `headers` is a NUL-terminated blob of "Key: Value\n" lines — one string
/// rather than a marshalled array, because the Zig side builds it once and this
/// avoids two allocations and a length-array per call.
///
/// The response body is written into a caller-provided buffer. Nothing is
/// allocated across the boundary, so there is no free() to forget.
int secretctl_http(const char *method,
                   const char *url,
                   const char *headers,
                   const unsigned char *body,
                   size_t body_len,
                   int timeout_ms,
                   int *out_status,
                   unsigned char *out_buf,
                   size_t out_cap,
                   size_t *out_len) {
    if (!method || !url || !out_status || !out_len) return SC_HTTP_BAD_ARGS;
    *out_status = 0;
    *out_len = 0;

    @autoreleasepool {
        NSURL *nsurl = [NSURL URLWithString:[NSString stringWithUTF8String:url]];
        if (!nsurl) return SC_HTTP_BAD_ARGS;
        // Refuse plaintext outright. An http:// endpoint would put signed
        // requests and sealed bodies on the wire in clear, and the only way
        // that URL gets here is a mistake or an attacker-supplied config.
        if (![[nsurl.scheme lowercaseString] isEqualToString:@"https"]) {
            return SC_HTTP_BAD_ARGS;
        }

        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:nsurl];
        req.HTTPMethod = [NSString stringWithUTF8String:method];
        req.timeoutInterval = (double)timeout_ms / 1000.0;
        // Approval requests must never be answered from a cache: a cached
        // verdict is a replayed verdict.
        req.cachePolicy = NSURLRequestReloadIgnoringLocalAndRemoteCacheData;

        if (headers && headers[0]) {
            NSString *blob = [NSString stringWithUTF8String:headers];
            for (NSString *line in [blob componentsSeparatedByString:@"\n"]) {
                if (line.length == 0) continue;
                NSRange colon = [line rangeOfString:@": "];
                if (colon.location == NSNotFound) continue;
                NSString *k = [line substringToIndex:colon.location];
                NSString *v = [line substringFromIndex:colon.location + colon.length];
                [req setValue:v forHTTPHeaderField:k];
            }
        }

        if (body && body_len > 0) {
            req.HTTPBody = [NSData dataWithBytes:body length:body_len];
        }

        NSURLSessionConfiguration *cfg =
            [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.timeoutIntervalForRequest = (double)timeout_ms / 1000.0;
        cfg.timeoutIntervalForResource = (double)timeout_ms / 1000.0;
        // No cookies, no credential store, no shared cache: this client has one
        // identity and it is a signature, not ambient session state.
        cfg.HTTPCookieStorage = nil;
        cfg.URLCache = nil;
        NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];

        // Everything the caller needs is copied out inside the completion
        // handler, before the semaphore is signalled. Nothing Objective-C
        // outlives the handler.
        //
        // The earlier shape kept `__block NSData *` alive across the wait and
        // read it afterwards, which is correct only because ARC retains on
        // assignment — so its correctness depended on -fobjc-arc being passed.
        // A probe build that omitted the flag segfaulted on the second request.
        // Copying here removes the dependency instead of documenting it.
        __block int status = 0;
        __block size_t copied = 0;
        __block int result = SC_HTTP_TRANSPORT;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        NSURLSessionDataTask *task =
            [session dataTaskWithRequest:req
                      completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                          if (e) {
                              result = (e.code == NSURLErrorTimedOut)
                                  ? SC_HTTP_TIMEOUT : SC_HTTP_TRANSPORT;
                          } else if (![r isKindOfClass:[NSHTTPURLResponse class]]) {
                              result = SC_HTTP_TRANSPORT;
                          } else {
                              status = (int)((NSHTTPURLResponse *)r).statusCode;
                              size_t n = d ? (size_t)d.length : 0;
                              if (n > out_cap) {
                                  result = SC_HTTP_BODY_TOO_BIG;
                              } else {
                                  if (n > 0 && out_buf) memcpy(out_buf, d.bytes, n);
                                  copied = n;
                                  result = SC_HTTP_OK;
                              }
                          }
                          dispatch_semaphore_signal(sem);
                      }];
        [task resume];

        // Bounded wait, with headroom over the request timeout so a hung
        // request surfaces as a timeout rather than blocking forever. The
        // unbounded DISPATCH_TIME_FOREVER in local_auth.m is exactly the bug
        // this avoids repeating.
        long waited = dispatch_semaphore_wait(
            sem, dispatch_time(DISPATCH_TIME_NOW,
                               (int64_t)(timeout_ms + 2000) * NSEC_PER_MSEC));
        if (waited != 0) {
            [task cancel];
            [session invalidateAndCancel];
            return SC_HTTP_TIMEOUT;
        }

        *out_status = status;
        *out_len = copied;
        [session finishTasksAndInvalidate];
        return result;
    }
}
