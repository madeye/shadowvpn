// Native macOS glue for the desktop GUI (compiled by build.rs, macOS only):
//
// - SMAppService wrappers to register/unregister the bundled
//   `shadowvpn-desktop-helper` as a launchd LaunchDaemon (root, always
//   available, no per-session password prompt). Requires macOS 13+ and the
//   app to run from a real .app bundle containing
//   Contents/Library/LaunchDaemons/<plist>.
// - An LAContext wrapper so the GUI can gate use of that always-root daemon
//   behind Touch ID / Apple Watch (with login-password fallback).
//
// All functions are blocking and safe to call from non-main threads (tauri
// command threads); LAContext presents its own UI on the right thread.

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <ServiceManagement/ServiceManagement.h>

static void copy_err(NSError *error, char *buf, size_t buflen) {
    if (!buf || buflen == 0) return;
    buf[0] = '\0';
    if (!error) return;
    const char *msg = error.localizedDescription.UTF8String;
    if (!msg) return;
    strlcpy(buf, msg, buflen);
}

// Status codes mirror SMAppServiceStatus:
//   0 = not registered, 1 = enabled, 2 = requires approval in System
//   Settings, 3 = plist not found in the bundle. -1 = SMAppService
//   unavailable (macOS < 13).
int svpn_daemon_status(const char *plist_name) {
    if (@available(macOS 13.0, *)) {
        @autoreleasepool {
            SMAppService *svc = [SMAppService
                daemonServiceWithPlistName:[NSString stringWithUTF8String:plist_name]];
            return (int)svc.status;
        }
    }
    return -1;
}

// 0 = registered (may still require approval — re-check status), -1 = error.
int svpn_daemon_register(const char *plist_name, char *err, size_t errlen) {
    if (@available(macOS 13.0, *)) {
        @autoreleasepool {
            SMAppService *svc = [SMAppService
                daemonServiceWithPlistName:[NSString stringWithUTF8String:plist_name]];
            NSError *error = nil;
            if ([svc registerAndReturnError:&error]) {
                return 0;
            }
            // "Operation not permitted" here usually means the user still has
            // to approve the daemon in System Settings > Login Items.
            copy_err(error, err, errlen);
            return -1;
        }
    }
    strlcpy(err, "SMAppService requires macOS 13 or later", errlen);
    return -1;
}

int svpn_daemon_unregister(const char *plist_name, char *err, size_t errlen) {
    if (@available(macOS 13.0, *)) {
        @autoreleasepool {
            SMAppService *svc = [SMAppService
                daemonServiceWithPlistName:[NSString stringWithUTF8String:plist_name]];
            NSError *error = nil;
            if ([svc unregisterAndReturnError:&error]) {
                return 0;
            }
            copy_err(error, err, errlen);
            return -1;
        }
    }
    strlcpy(err, "SMAppService requires macOS 13 or later", errlen);
    return -1;
}

void svpn_open_login_items(void) {
    if (@available(macOS 13.0, *)) {
        [SMAppService openSystemSettingsLoginItems];
    }
}

// Authenticate the user as the device owner: Touch ID / Apple Watch first,
// login password as the system-provided fallback.
//   1 = authenticated, 0 = denied or cancelled, -1 = policy unavailable.
int svpn_authenticate_user(const char *reason, char *err, size_t errlen) {
    @autoreleasepool {
        LAContext *ctx = [[LAContext alloc] init];
        NSError *error = nil;
        if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
            copy_err(error, err, errlen);
            return -1;
        }
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block int result = 0;
        __block NSError *replyError = nil;
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
            localizedReason:[NSString stringWithUTF8String:reason]
                      reply:^(BOOL success, NSError *e) {
                        result = success ? 1 : 0;
                        replyError = e;
                        dispatch_semaphore_signal(sem);
                      }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        if (result != 1) {
            copy_err(replyError, err, errlen);
        }
        return result;
    }
}
