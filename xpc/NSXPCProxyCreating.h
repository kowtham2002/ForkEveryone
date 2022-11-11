//
//  NSXPCProxyCreating.h
//  blasthound
//
//  Created by bluedog on 2/23/21.
//

@protocol NSXPCProxyCreating

@optional
-(id)synchronousRemoteObjectProxyWithErrorHandler:(/*^block*/id)arg1;
@required
-(id)remoteObjectProxyWithErrorHandler:(/*^block*/id)arg1;
-(id)remoteObjectProxy;
@end
