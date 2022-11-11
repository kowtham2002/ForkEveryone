
//  main.m
//  appleDRM
//
//  Created by failbr34k on 2021-08-27.
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import "sysGroupPath.h"
#import "libMobileGestalt.h"
#import <Block.h>
#import <Security/Security.h>
#import <mach-o/dyld.h>
#import <sys/types.h>
#import <mach-o/nlist.h>
#import "SecItemPriv.h"
#import "SecKeyPriv.h"
#import "SecPolicyPriv.h"
#import "SecTrustPriv.h"
#import "SecAccessControlPriv.h"


static void createRK(void)
{
       
    NSError *error = nil;
    CFAllocatorRef allocator = kCFAllocatorDefault;
    CFTypeRef protection = kSecAttrAccessibleAlwaysThisDeviceOnlyPrivate;
    CFErrorRef cferror = NULL;
    SecAccessControlRef AccessControl = SecAccessControlCreateWithFlags(allocator, protection, kSecAccessControlPrivateKeyUsage, &cferror);
    if (!AccessControl) {
        NSLog(@"Failed to create access control.");
        return ;
    }
    CFStringRef systemGroupPath = NULL;
    const char* systemGroupName = NULL;
    systemGroupName = "systemgroup.com.apple.mobileactivationd";
    systemGroupPath = GetSystemGroupPath(systemGroupName);
    NSString *uikPath = nil;
    uikPath = (__bridge NSString *)systemGroupPath;
    uikPath = [uikPath stringByAppendingPathComponent: @"Library/uik/"];
    
    NSFileManager *fileManager = [[NSFileManager alloc] init];
    
    BOOL isDir;
    BOOL isFound;
    NSString *uikCertificate = [uikPath stringByAppendingPathComponent: @"uik.pem"];
    isFound = [fileManager fileExistsAtPath: uikCertificate isDirectory: &isDir];
    if (isFound == YES) {
        
        SecAccessControlRef AccessControlRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAlwaysThisDeviceOnlyPrivate, kSecAccessControlPrivateKeyUsage, NULL);
        if (!AccessControlRef) {
            NSLog(@"Failed to create access control.");
            return;
        }

        NSMutableDictionary *keyAttributesRef = [[NSMutableDictionary alloc] init];
        [keyAttributesRef setObject:(id)kSecAttrTokenIDSecureEnclave forKey:(id)kSecAttrTokenID ];
        [keyAttributesRef setObject:(id)kSecAttrKeyTypeECSECPrimeRandom forKey:(id)kSecAttrKeyType ];
        [keyAttributesRef setObject:CFBridgingRelease(AccessControlRef) forKey:(id)kSecAttrAccessControl ];
        [keyAttributesRef setObject:[NSNumber numberWithBool:NO] forKey:(id)kSecAttrIsPermanent ];

        
        NSDictionary *UIKkeyAttributes = @{
        (id)kSecAttrTokenID : (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrAccessControl : (__bridge id)AccessControl,
        (id)kSecAttrIsPermanent : @NO};
        
        NSDictionary *keyAttributesSign = @{
            (id)kSecAttrTokenID : (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrAccessControl : (__bridge id)AccessControlRef,
            (id)kSecAttrIsPermanent : @NO
        };

        
        BOOL HasPKA = MGGetBoolAnswer(CFSTR("HasPKA"));
        if ( HasPKA == false ) {
            NSLog(@"PKA return Null or false, using non PKA EC key.");
            
            UIKkeyAttributes = @{
            (id)kSecAttrTokenID : (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrAccessControl : (__bridge id)AccessControl,
            (id)kSecAttrIsPermanent : @NO
        };
            
            [keyAttributesRef setObject:(id)kSecAttrKeyTypeECSECPrimeRandom forKey:(id)kSecAttrKeyType ];
            
            keyAttributesSign = @{
                (id)kSecAttrTokenID : (id)kSecAttrTokenIDSecureEnclave,
                (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
                (id)kSecAttrAccessControl : (__bridge id)AccessControlRef,
                (id)kSecAttrIsPermanent : @NO
            };

            
        } else {
            NSLog(@"HasPKA true");
        }

            NSDictionary *keyAttributes = @{
            (id)kSecAttrTokenID : (id)kSecAttrTokenIDAppleKeyStore,
            (id)kSecAttrKeyType : (id)kSecAttrKeyTypeSecureEnclaveAttestation,
            (id)kSecAttrAccessControl : (__bridge id)AccessControl,
            (id)kSecAttrIsPermanent : @NO
        };
        
        
        SecKeyRef uikAttestationKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyAttributes, (void *)&error);
            
        if(!uikAttestationKey) {
            NSLog(@"Failed to create AttesationKey.");
            return;
        }
            
        NSLog(@"uikAttestationKey: %@",uikAttestationKey);

        
        NSData* uikCertificateData = [NSData dataWithContentsOfFile:uikCertificate];
        if(!uikCertificateData) {
            NSLog(@"Failed to load %@.", uikCertificate);
            return;
        }

        NSLog(@"uikCertificate: %@",uikCertificate);
       

        NSDictionary *storekeyAttributes = @{
            (id)kSecAttrTokenID : (id)kSecAttrTokenIDSecureEnclave,
            (id)kSecAttrTokenOID : (id)uikCertificateData,
            (id)kSecAttrAccessControl : (__bridge id)AccessControl,
            (id)kSecAttrIsPermanent : @NO
        };
        
        
        SecKeyRef uikPrivateKey = SecKeyCreateWithData((__bridge CFDataRef)uikCertificateData, (__bridge CFDictionaryRef)storekeyAttributes, (void *)&error);
        if(!uikPrivateKey) {
            NSLog(@"Failed to convert UIK.");
            return;
        }
        
        NSLog(@"uikPrivateKey (signing key): %@",uikPrivateKey);
        
        SecKeyRef UIKPub = SecKeyCopyPublicKey(uikPrivateKey);
        if (!UIKPub)
        {
            NSLog(@"Failed to get uik pub.");
            return;
        }
        
        
        NSLog(@"uikPublic : %@",UIKPub);
        
        NSData *UIKPubKey = CFBridgingRelease(SecKeyCopyExternalRepresentation(UIKPub, (void *)&error));
        NSLog(@"UIKPublicKey: %@",[UIKPubKey base64EncodedStringWithOptions:0]);
        
        
        SecKeyRef SIKAttestationKey = SecKeyCopyAttestationKey(kSecKeyAttestationKeyTypeSIK, (void *)&error);
        if (!SIKAttestationKey) {
            NSLog(@"Failed to copy SIK attestation key.");
            return;
        }
        
        NSData* SIKattestation = (__bridge NSData *)SecKeyCreateAttestation(SIKAttestationKey, uikAttestationKey, &cferror);
        NSString* b64SIKatt = [SIKattestation base64EncodedStringWithOptions:0];
        NSLog(@"SIKAttestation: %@",b64SIKatt);
        NSData* UIKAttestation = (__bridge NSData *)SecKeyCreateAttestation(uikPrivateKey, uikAttestationKey, &cferror);
        NSString* b64UIKatt = [UIKAttestation base64EncodedStringWithOptions:0];
        NSLog(@"UIKAttestation: %@",b64UIKatt);


        AccessControlRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAlwaysThisDeviceOnlyPrivate, kSecAccessControlPrivateKeyUsage, NULL);
        if (!AccessControlRef) {
            NSLog(@"Failed to create access control.");
            return;
        }

        SecKeyRef RefKey = SecKeyCreateRandomKey((CFDictionaryRef)keyAttributesRef, (void *)&error);
        if (!RefKey) {
            NSLog(@"Failed to create ref key. %@", [error localizedDescription] );
            return;
        }
        NSLog(@"RK signing key: %p",RefKey);

    }else{
        
        SecAccessControlRef AccessControlRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAlwaysThisDeviceOnlyPrivate, kSecAccessControlPrivateKeyUsage, NULL);
        if (!AccessControlRef) {
            NSLog(@"Failed to create access control.");
            return;
        }

        NSMutableDictionary *keyAttributesRef = [[NSMutableDictionary alloc] init];
        [keyAttributesRef setObject:(id)kSecAttrTokenIDAppleKeyStore forKey:(id)kSecAttrTokenID ];
        [keyAttributesRef setObject:(id)kSecAttrKeyTypeECSECPrimeRandom forKey:(id)kSecAttrKeyType ];
        [keyAttributesRef setObject:CFBridgingRelease(AccessControlRef) forKey:(id)kSecAttrAccessControl ];
        [keyAttributesRef setObject:[NSNumber numberWithBool:NO] forKey:(id)kSecAttrIsPermanent ];

        
        NSDictionary *UIKkeyAttributes = @{
        (id)kSecAttrTokenID : (id)kSecAttrTokenIDAppleKeyStore,
        (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrAccessControl : (__bridge id)AccessControl,
        (id)kSecAttrIsPermanent : @NO};
        
        BOOL HasPKA = MGGetBoolAnswer(CFSTR("HasPKA"));
        if ( HasPKA == false ) {
            NSLog(@"PKA return Null or false, using non PKA EC key.");
            
            UIKkeyAttributes = @{
            (id)kSecAttrTokenID : (id)kSecAttrTokenIDAppleKeyStore,
            (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrAccessControl : (__bridge id)AccessControl,
            (id)kSecAttrIsPermanent : @NO
        };
            
            [keyAttributesRef setObject:(id)kSecAttrKeyTypeECSECPrimeRandom forKey:(id)kSecAttrKeyType ];
            
        } else {
            NSLog(@"HasPKA true");
        }
        
            NSDictionary *keyAttributes = @{
            (id)kSecAttrTokenID : (id)kSecAttrTokenIDAppleKeyStore,
        (id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeSecureEnclaveAttestation,
            (id)kSecAttrAccessControl : (__bridge id)AccessControl,
            (id)kSecAttrIsPermanent : @NO
        };
        
        
        SecKeyRef uikAttestationKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyAttributes, (void *)&error);
        if(!uikAttestationKey) {
            NSLog(@"Failed to create AttesationKey.");
            return;
        }
    
        NSLog(@"uikAttestationKey: %@",uikAttestationKey);
        
    SecKeyRef uikPrivateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef) UIKkeyAttributes, &cferror);
        NSLog(@"uikPriv: %@",uikPrivateKey);
        SecKeyRef UIKPub = SecKeyCopyPublicKey(uikPrivateKey);
        if (!UIKPub)
        {
            NSLog(@"Failed to get uik pub.");
            return;
        }
        NSData *UIKPubKey = CFBridgingRelease(SecKeyCopyExternalRepresentation(UIKPub, (void *)&error));
        NSLog(@"UIKPublicKey: %@",[UIKPubKey base64EncodedStringWithOptions:0]);

        SecKeyRef SIKAttestationKey = SecKeyCopyAttestationKey(kSecKeyAttestationKeyTypeSIK, (void *)&error);
        if (!SIKAttestationKey) {
            NSLog(@"Failed to copy SIK attestation key.");
            return;
        }
        NSLog(@"SIK: %@",SIKAttestationKey);
        NSDictionary* sikattr = (__bridge NSDictionary*)SecKeyCopyAttributes(SIKAttestationKey);
       
        [sikattr writeToFile:@"/tmp/sikattributes.plist" atomically:YES];
        
        NSDictionary* dict = [NSDictionary dictionaryWithContentsOfFile:@"/tmp/sikattributes.plist"];
        NSLog(@"dict:\n%@",dict);
    NSData* SIKattestation = (__bridge NSData *)SecKeyCreateAttestation(SIKAttestationKey, uikAttestationKey, &cferror);
    NSString* b64SIKatt = [SIKattestation base64EncodedStringWithOptions:0];
    NSLog(@"SIKAttestation: %@",b64SIKatt);
    NSData* UIKAttestation = (__bridge NSData *)SecKeyCreateAttestation(SIKAttestationKey, uikPrivateKey, &cferror);
    NSString* b64UIKatt = [UIKAttestation base64EncodedStringWithOptions:0];
    NSLog(@"UIKAttestation: %@",b64UIKatt);


        SecKeyRef RefKey = SecKeyCreateRandomKey((CFDictionaryRef)keyAttributesRef, (void *)&error);
        if (!RefKey) {
            NSLog(@"Failed to create ref key. %@", [error localizedDescription] );
            return;
        }
        NSLog(@"refkey: %@", RefKey );

    }
    return;
}

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        createRK();
    }
}

        AccessControlRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAlwaysThisDeviceOnlyPrivate, kSecAccessControlPrivateKeyUsage, NULL);
        if (!AccessControlRef) {
            NSLog(@"Failed to create access control.");
            return;
        }

        SecKeyRef RefKey = SecKeyCreateRandomKey((CFDictionaryRef)keyAttributesRef, (void *)&error);
        if (!RefKey) {
            NSLog(@"Failed to create ref key. %@", [error localizedDescription] );
            return;
        }
        se64EncodedStringWithOptions:0]);
        
        
        SecKeyRef SIKAttestationKey = SecKeyCopyAttestationKey(kSecKeyAttestationKeyTypeSIK, (void *)&error);
        if (!SIKAttestationKey) {
            NSLog(@"Failed to copy SIK attestation key.");
            return;
        }
        
        NSData* SIKattestation = (__bridge NSData *)SecKeyCreateAttestation(SIKAttestationKey, uikAttestationKey, &cferror);
        NSString* b64SIKatt = [SIKattestation base64EncodedStringWithOptions:0];
        NSLog(@"SIKAttestation: %@",b64SIKatt);
        NSData* UIKAttestation = (__bridge NSData *)SecKeyCreateAttestation(uikPrivateKey, uikAttestationKey, &cferror);
        NSString* b64UIKatt = [UIKAttestation base64EncodedStringWithOptions:
