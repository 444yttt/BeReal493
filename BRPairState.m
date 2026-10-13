#import "BRPairState.h"

@implementation BRSelectedPair
- (instancetype)initWithBack:(NSData *)back front:(NSData *)front expires:(NSDate *)expires {
    if (!back.length || !front.length || !expires) return nil;
    if ((self = [super init])) {
        _back = [back copy]; _front = [front copy]; _expires = [expires copy];
    }
    return self;
}
@end

@interface BRPairState ()
@property(nonatomic, strong) BRSelectedPair *active;
@property(nonatomic) NSUInteger consumed;
@end

@implementation BRPairState
- (void)arm:(BRSelectedPair *)pair { @synchronized(self) { self.active = pair; self.consumed = 0; } }
- (void)clear { [self arm:nil]; }
- (BRSelectedPair *)currentAt:(NSDate *)date {
    @synchronized(self) {
        if (self.active && [self.active.expires compare:date] != NSOrderedDescending) [self clear];
        return self.active;
    }
}
- (BOOL)consume:(BRPhotoRole)role pair:(BRSelectedPair *)pair {
    @synchronized(self) {
        if (!pair || pair != self.active || (role != BRPhotoRoleBack && role != BRPhotoRoleFront)) return NO;
        self.consumed |= role;
        if (self.consumed == (BRPhotoRoleBack | BRPhotoRoleFront)) { [self clear]; return YES; }
        return NO;
    }
}
@end
