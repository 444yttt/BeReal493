// Independent prototype. This DOES NOT submit a BeReal post.
// The two selected pictures are held in memory for a future, version-specific camera adapter.
#import <UIKit/UIKit.h>
#import <PhotosUI/PhotosUI.h>
#import <objc/runtime.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@interface BRPhotoPickerBridge : NSObject <PHPickerViewControllerDelegate>
@property(nonatomic,strong) UIButton *button;
@property(nonatomic,strong) NSMutableArray<UIImage *> *photos;
@property(nonatomic,assign) BOOL presenting;
+ (instancetype)shared;
- (void)attach;
@end

@implementation BRPhotoPickerBridge
+ (instancetype)shared { static BRPhotoPickerBridge *shared; static dispatch_once_t once; dispatch_once(&once, ^{ shared=[self new]; shared.photos=[NSMutableArray array]; }); return shared; }
- (UIWindow *)activeWindow {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] || scene.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) if (window.isKeyWindow) return window;
    }
    return nil;
}
- (void)attach {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window=[self activeWindow]; if (!window) return;
        if (!self.button) {
            UIButton *b=[UIButton buttonWithType:UIButtonTypeSystem];
            b.frame=CGRectMake(12, 145, 128, 42);
            b.backgroundColor=[UIColor colorWithWhite:0.08 alpha:0.9];
            b.layer.cornerRadius=12;
            [b setTitle:@"📷 写真を選択" forState:UIControlStateNormal];
            [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            b.titleLabel.font=[UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
            [b addTarget:self action:@selector(openPicker) forControlEvents:UIControlEventTouchUpInside]; self.button=b;
        }
        if (self.button.superview != window) [window addSubview:self.button];
    });
}
- (void)openPicker {
    if (self.presenting) return;
    UIWindow *window=[self activeWindow]; UIViewController *vc=window.rootViewController;
    while (vc.presentedViewController) vc=vc.presentedViewController;
    if (!vc) return;
    PHPickerConfiguration *config=[[PHPickerConfiguration alloc] init];
    config.filter=[PHPickerFilter imagesFilter]; config.selectionLimit=2;
    PHPickerViewController *picker=[[PHPickerViewController alloc] initWithConfiguration:config];
    picker.delegate=self; self.presenting=YES; [vc presentViewController:picker animated:YES completion:nil];
}
- (void)picker:(PHPickerViewController *)picker didFinishPicking:(NSArray<PHPickerResult *> *)results {
    [picker dismissViewControllerAnimated:YES completion:nil]; self.presenting=NO;
    [self.photos removeAllObjects];
    if (results.count != 2) { NSLog(@"[BRPhotoPrototype] Select exactly two images"); return; }
    // Preserve the original selection order even when asynchronous photo loads finish out of order.
    dispatch_group_t group=dispatch_group_create();
    NSMutableArray *slots=[NSMutableArray arrayWithObjects:NSNull.null,NSNull.null,nil];
    [results enumerateObjectsUsingBlock:^(PHPickerResult *result, NSUInteger index, BOOL *stop) {
        if (![result.itemProvider canLoadObjectOfClass:UIImage.class]) return;
        dispatch_group_enter(group);
        [result.itemProvider loadObjectOfClass:UIImage.class completionHandler:^(id<NSItemProviderReading> object, NSError *error) {
            @synchronized(slots) { if ([object isKindOfClass:UIImage.class]) slots[index]=object; }
            dispatch_group_leave(group);
        }];
    }];
    dispatch_group_notify(group, dispatch_get_main_queue(), ^{
        for (id value in slots) if ([value isKindOfClass:UIImage.class]) [self.photos addObject:value];
        NSLog(@"[BRPhotoPrototype] Selected %lu images. NOT uploaded.",(unsigned long)self.photos.count);
        // A future adapter can observe this explicit handoff without tying photo selection
        // to an unverified private BeReal selector. The images never leave this process here.
        if (self.photos.count == 2) {
            [[NSNotificationCenter defaultCenter] postNotificationName:@"BRPrototypeTwoPhotosReady"
                                                                object:self
                                                              userInfo:@{@"front":self.photos[0], @"back":self.photos[1]}];
        }
        NSString *message=self.photos.count==2 ? @"写真2枚を読み込みました。現在は投稿機能には接続していません。" : @"2枚の画像を読み込めませんでした。";
        UIWindow *window=[self activeWindow]; UIViewController *vc=window.rootViewController;
        while (vc.presentedViewController) vc=vc.presentedViewController;
        UIAlertController *alert=[UIAlertController alertControllerWithTitle:@"Camera Roll Prototype" message:message preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [vc presentViewController:alert animated:YES completion:nil];
    });
}
@end

__attribute__((constructor)) static void BRPrototypeInit(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) { [[BRPhotoPickerBridge shared] attach]; }];
        [[BRPhotoPickerBridge shared] attach];
    });
}
