//
//  sysGroupPath.h
//  issueClientCertificate
//
//  Created by failbr34k on 2022-10-30.
//

/*
    for ios 12 to 14 this is how you get the system group path for mobileactivationd
    to access the committed UIK's signing key
    which is stored as raw DER data and named uik.pem
    this data can be read as asn.1 and is base64 encoded data.
 */


#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>

typedef enum : unsigned long long {
    /* everything is fine */
    CONTAINER_ERROR_OKAY            = 0,
    /* a syscall failed -- check errno */
    CONTAINER_ERROR_SYSTEM          = -1,
    /* an internal sanity check failed */
    CONTAINER_ERROR_SANITY          = -2,
    /* invalid argument */
    CONTAINER_ERROR_ARG             = -3,
    /* refused to run as root */
    CONTAINER_ERROR_ROOT            = -4,
    /* failed to setup the user namespace */
    CONTAINER_ERROR_USER            = -5,
    /* failed to set the hostname of container */
    CONTAINER_ERROR_NET_HOSTNAME    = -6,
    /* failed to create TAP device in network namespace */
    CONTAINER_ERROR_NET_TAP         = -7,
    /* failed to configure devices in the network namespace */
    CONTAINER_ERROR_NET_IFCONFIG    = -8,
    /* failed to start the network relay */
    CONTAINER_ERROR_NET_RELAY       = -9,
    /* failed to create the tty */
    CONTAINER_ERROR_TTY             = -10,
} container_error_t;

extern const char* _Nullable container_system_group_path_for_identifier(void* _Nullable ret, const char* _Nullable systemGroupName, container_error_t* _Nullable error);
extern CFStringRef _Nullable GetSystemPath(const char* _Nullable bundleID);
static CFStringRef _Nullable GetSystemGroupPath(const char* _Nullable systemGroupName)
{
    CFStringRef containerPath = NULL;
    container_error_t localError = CONTAINER_ERROR_OKAY;

    const char *containerCStringPath = container_system_group_path_for_identifier(NULL, systemGroupName, &localError);
    //printf("containerCStringPath: %s", containerCStringPath);
    if (containerCStringPath) {
        containerPath = CFStringCreateWithCString(NULL, containerCStringPath, kCFStringEncodingUTF8);
        //NSString *containerPathNS = (__bridge NSString *)containerPath;
        //NSLog(@"%@", containerPathNS);
        free((void *)containerCStringPath);
    }

    if (containerPath) {
        return containerPath;
    }
    return 0;
}
