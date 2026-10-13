#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, BRPhotoRole) {
    BRPhotoRoleBack = 1,
    BRPhotoRoleFront = 2,
};

@interface BRSelectedPair : NSObject
@property(nonatomic, readonly) NSData *back;
@property(nonatomic, readonly) NSData *front;
@property(nonatomic, readonly) NSDate *expires;
- (instancetype)initWithBack:(NSData *)back front:(NSData *)front expires:(NSDate *)expires;
@end

@interface BRPairState : NSObject
- (void)arm:(BRSelectedPair *)pair;
- (void)clear;
- (BRSelectedPair *)currentAt:(NSDate *)date;
- (BOOL)consume:(BRPhotoRole)role pair:(BRSelectedPair *)pair;
@end
