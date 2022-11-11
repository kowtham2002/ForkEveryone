//
//  MACollectionInterface.m
//  br34kdown
//
//  Created by fail on 2022-07-29.
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>
#import "SecKeyPriv.h"
#import "DeviceIdentitySPI.h"
#import "SecIdentityPriv.h"
#import "SecItemPriv.h"
#import "libMobileGestalt.h"


static void performCollection(void);

void performCollection(void)
{
    id IngestData = nil;
    id signingKeyPublicKey = nil;
    id signingAttestation = nil;
    id ingestURL = nil;
    id SIK = nil;
    id pcrt = nil;
    id signature = nil;
    NSError * error = nil;
    CFErrorRef* cerror = nil;

    
    [ingestURL copyIngestURL];
    [signingAttestation collectSigningAttestation:&error];
    [SIK collectSIK:&error];
    [pcrt collectPCRT:&error];
    [signingKeyPublicKey signingKeyPublicKeyWithError:&error];
    [IngestData copyIngestData:&error];
    [signature signatureForData:IngestData error:&error];
    
    bool rn = SecKeyVerifySignature((__bridge SecKeyRef)signingKeyPublicKey, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, (__bridge CFDataRef)IngestData, (__bridge CFDataRef)signature, cerror);
    
    if (rn == YES)
    {
        NSLog(@"creating DRM request");
        
        NSDictionary* collectionBlobDict = @{(NSString*)(@"IngestBody") : IngestData,
                                             (NSString*)(@"X-Apple-Sig-Key") : signingKeyPublicKey,
                                             (NSString*)(@"X-Apple-Signature") : signature
                                            };
        NSError* nerror = nil;
        NSData* collectionData = [NSPropertyListSerialization dataWithPropertyList:collectionBlobDict format:NSPropertyListXMLFormat_v1_0 options:0 error:&nerror];
        
        NSData* handshakeReqMsg = [(NSString*)(@"gokNoxXYmlDWxtIfmoBq+VCL4h7w") dataUsingEncoding:NSUTF8StringEncoding];
        
        NSDictionary* RequestDict = @{(NSString*)(@"CollectionBlob") : collectionData,
                                     (NSString*)(@"HandshakeRequestMessage") : handshakeReqMsg,
                                     (NSString*)(@"UniqueDeviceID") : (NSString*)(@"188c98ce31b23201f7670a21513d8fe46741e254")
                                    };
        
        NSData *drmSer = [NSPropertyListSerialization dataWithPropertyList:RequestDict format:NSPropertyListXMLFormat_v1_0 options:0 error: &nerror];
        
        NSString* DRM = [[NSString alloc] initWithData:drmSer encoding:NSUTF8StringEncoding];
        
        [DRM writeToFile:@"/failbr34k/DRMRequest.plist" atomically:YES];
        
        NSLog(@"\n%@",DRM);
    }
    else
    {NSLog(@"DRM signature could not be verified, your POST will fail.");}
}


