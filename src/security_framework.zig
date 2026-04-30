//! Minimal Apple Security.framework / CoreFoundation bindings.
//! Just enough to add/get/delete a generic password item in the Keychain.

const std = @import("std");

pub const CFTypeRef = ?*anyopaque;
pub const CFStringRef = ?*anyopaque;
pub const CFDataRef = ?*anyopaque;
pub const CFDictionaryRef = ?*anyopaque;
pub const CFMutableDictionaryRef = ?*anyopaque;
pub const CFAllocatorRef = ?*anyopaque;
pub const CFIndex = c_long;
pub const OSStatus = i32;
pub const Boolean = u8;

pub const errSecSuccess: OSStatus = 0;
pub const errSecItemNotFound: OSStatus = -25300;
pub const errSecDuplicateItem: OSStatus = -25299;
pub const errSecAuthFailed: OSStatus = -25293;

pub const kCFStringEncodingUTF8: u32 = 0x08000100;

pub extern "CoreFoundation" const kCFAllocatorDefault: CFAllocatorRef;
pub extern "CoreFoundation" const kCFTypeDictionaryKeyCallBacks: anyopaque;
pub extern "CoreFoundation" const kCFTypeDictionaryValueCallBacks: anyopaque;

pub extern "CoreFoundation" fn CFRelease(cf: CFTypeRef) void;
pub extern "CoreFoundation" fn CFRetain(cf: CFTypeRef) CFTypeRef;
pub extern "CoreFoundation" fn CFStringCreateWithBytes(
    alloc: CFAllocatorRef,
    bytes: [*]const u8,
    numBytes: CFIndex,
    encoding: u32,
    isExternal: Boolean,
) CFStringRef;
pub extern "CoreFoundation" fn CFDataCreate(
    alloc: CFAllocatorRef,
    bytes: [*]const u8,
    length: CFIndex,
) CFDataRef;
pub extern "CoreFoundation" fn CFDataGetLength(theData: CFDataRef) CFIndex;
pub extern "CoreFoundation" fn CFDataGetBytePtr(theData: CFDataRef) [*]const u8;
pub extern "CoreFoundation" fn CFDictionaryCreateMutable(
    alloc: CFAllocatorRef,
    capacity: CFIndex,
    keyCallBacks: ?*const anyopaque,
    valueCallBacks: ?*const anyopaque,
) CFMutableDictionaryRef;
pub extern "CoreFoundation" fn CFDictionarySetValue(
    theDict: CFMutableDictionaryRef,
    key: ?*const anyopaque,
    value: ?*const anyopaque,
) void;

pub extern "Security" const kSecClass: CFStringRef;
pub extern "Security" const kSecClassGenericPassword: CFStringRef;
pub extern "Security" const kSecAttrService: CFStringRef;
pub extern "Security" const kSecAttrAccount: CFStringRef;
pub extern "Security" const kSecValueData: CFStringRef;
pub extern "Security" const kSecReturnData: CFStringRef;
pub extern "Security" const kSecMatchLimit: CFStringRef;
pub extern "Security" const kSecMatchLimitOne: CFStringRef;
pub extern "Security" const kSecAttrAccessible: CFStringRef;
pub extern "Security" const kSecAttrAccessibleWhenUnlocked: CFStringRef;
pub extern "Security" const kCFBooleanTrue: CFTypeRef;

pub extern "Security" fn SecItemAdd(attributes: CFDictionaryRef, result: ?*CFTypeRef) OSStatus;
pub extern "Security" fn SecItemCopyMatching(query: CFDictionaryRef, result: ?*CFTypeRef) OSStatus;
pub extern "Security" fn SecItemDelete(query: CFDictionaryRef) OSStatus;

/// Helper: create a CFString from a Zig slice. Caller must CFRelease.
pub fn cfString(bytes: []const u8) ?CFStringRef {
    return CFStringCreateWithBytes(kCFAllocatorDefault, bytes.ptr, @intCast(bytes.len), kCFStringEncodingUTF8, 0);
}

/// Helper: create a CFData from a Zig slice. Caller must CFRelease.
pub fn cfData(bytes: []const u8) ?CFDataRef {
    return CFDataCreate(kCFAllocatorDefault, bytes.ptr, @intCast(bytes.len));
}
