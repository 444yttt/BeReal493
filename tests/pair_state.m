#import <Foundation/Foundation.h>
#import "../BRPairState.h"
static void require(BOOL condition, NSString *message) {
    if (!condition) { NSLog(@"FAIL: %@", message); exit(1); }
}
int main(void) {
    @autoreleasepool {
        NSDate *now = [NSDate date];
        NSData *back = [@"back" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *front = [@"front" dataUsingEncoding:NSUTF8StringEncoding];
        BRPairState *state = [BRPairState new];
        BRSelectedPair *a = [[BRSelectedPair alloc] initWithBack:back front:front expires:[now dateByAddingTimeInterval:60]];
        [state arm:a];
        require([[state currentAt:now].back isEqual:back], @"back assignment");
        require(![state consume:BRPhotoRoleFront pair:a], @"front first does not clear back");
        require([state currentAt:now] == a, @"one role keeps pair");
        require(![state consume:BRPhotoRoleFront pair:a], @"duplicate callback does not count as both cameras");
        require([state consume:BRPhotoRoleBack pair:a], @"both roles clear pair");
        require([state currentAt:now] == nil, @"pair used only once");
        BRSelectedPair *b = [[BRSelectedPair alloc] initWithBack:front front:back expires:[now dateByAddingTimeInterval:60]];
        [state arm:a]; [state arm:b];
        require(![state consume:BRPhotoRoleBack pair:a], @"stale callback cannot consume new pair");
        require(![state consume:0 pair:b], @"unknown camera is rejected");
        require([state currentAt:now] == b, @"new pair survives stale callback");
        require([state currentAt:[now dateByAddingTimeInterval:61]] == nil, @"expired pair clears");
        require([[BRSelectedPair alloc] initWithBack:[NSData data] front:front expires:now] == nil, @"empty data rejected");
        puts("Pair state tests passed");
    }
    return 0;
}
