#import <UIKit/UIKit.h>
#import <PhotosUI/PhotosUI.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>
#import "BRPairState.h"
#import "BRBundleIdentity.h"
#import "BRFrontOrientation.h"

static BRPairState *BRState;
static const void *BRReplacementKey = &BRReplacementKey;
static const void *BRPendingKey = &BRPendingKey;
static NSMutableSet<NSString *> *BRHookedDelegates;
static NSMutableSet<NSString *> *BRHookedPhotos;
static NSObject *BRHookLock;
static NSString *const BRStatusNote = @"BRCameraRollStatus";
static NSData *BRJPEG(UIImage *image);

static NSData *BRFrontProcessorData(NSData *data) {
    UIImage *image = [UIImage imageWithData:data];
    CGImageRef pixels = BRCreateLeftMirroredPixels(image.CGImage);
    if (!pixels) return nil;
    UIImage *prepared = [UIImage imageWithCGImage:pixels scale:1 orientation:UIImageOrientationUp];
    CGImageRelease(pixels);
    return BRJPEG(prepared);
}
typedef id (*BRDefaultsInitializer)(id object __attribute__((ns_consumed)), SEL, NSString *) __attribute__((ns_returns_retained));
static BRDefaultsInitializer BRDefaultsOriginal;
static id BRDefaultsInit(id defaults __attribute__((ns_consumed)), SEL selector, NSString *suite) __attribute__((ns_returns_retained));
static id BRDefaultsInit(id defaults __attribute__((ns_consumed)), SEL selector, NSString *suite) {
    return BRDefaultsOriginal(defaults,selector,[suite isEqualToString:@"group.BeReal"]?@"com.ayato.bereal493.shared":suite);
}

static void BRStatus(NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:BRStatusNote object:nil userInfo:@{@"message":message}];
    });
}
static BOOL BRMethodMatches(Method method, char returnType, unsigned int count) {
    if (!method || method_getNumberOfArguments(method) != count) return NO;
    char result[16]; method_getReturnType(method, result, sizeof(result));
    if (result[0] != returnType) return NO;
    for (unsigned int i=0; i<count; ++i) {
        char type[16]; method_getArgumentType(method, i, type, sizeof(type));
        if (type[0] != (i==1 ? ':' : '@')) return NO;
    }
    return YES;
}
static void BRInstallSandboxGroupFallback(void) {
    // The Ad Hoc variant cannot claim the original developer's App Group.
    // Keep root-app storage inside this app's sandbox; never grant cross-app access.
    if (!BRBundleIdentityAllowsSandboxFallback(NSBundle.mainBundle.bundleIdentifier.UTF8String)) return;
    SEL containerSelector=@selector(containerURLForSecurityApplicationGroupIdentifier:);
    Method containerMethod=class_getInstanceMethod(NSFileManager.class,containerSelector);
    if (BRMethodMatches(containerMethod,'@',3)) {
        NSURL *(*original)(id,SEL,NSString *)=(void *)method_getImplementation(containerMethod);
        IMP replacement=imp_implementationWithBlock(^NSURL *(NSFileManager *manager,NSString *group) {
            NSURL *result=original(manager,containerSelector,group);
            if (result || ![group isEqualToString:@"group.BeReal"]) return result;
            NSURL *support=[manager URLForDirectory:NSApplicationSupportDirectory inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:nil];
            NSURL *local=[support URLByAppendingPathComponent:@"BeRealShared" isDirectory:YES];
            if (![manager createDirectoryAtURL:local withIntermediateDirectories:YES attributes:nil error:nil]) return nil;
            return local;
        });
        method_setImplementation(containerMethod,replacement);
    }
    SEL defaultsSelector=@selector(initWithSuiteName:);
    Method defaultsMethod=class_getInstanceMethod(NSUserDefaults.class,defaultsSelector);
    if (BRMethodMatches(defaultsMethod,'@',3)) {
        BRDefaultsOriginal=(BRDefaultsInitializer)method_getImplementation(defaultsMethod);
        method_setImplementation(defaultsMethod,(IMP)BRDefaultsInit);
    }
}
static BOOL BRKnownDelegate(Class cls) {
    NSString *name = NSStringFromClass(cls);
    // Both classes and their ObjC ABI are verified in the supplied 4.93.0 binary.
    return [name isEqualToString:@"CameraKitData.PhotoCaptureDelegate"] ||
           [name isEqualToString:@"_TtC13CameraKitData20PhotoCaptureDelegate"] ||
           [name isEqualToString:@"Camera.CameraPhotoCaptureProcessor"] ||
           [name isEqualToString:@"_TtC6Camera27CameraPhotoCaptureProcessor"];
}
static BRPhotoRole BRRoleForOutput(AVCapturePhotoOutput *output) {
    AVCaptureDevicePosition position = AVCaptureDevicePositionUnspecified;
    for (AVCaptureConnection *connection in output.connections) {
        for (AVCaptureInputPort *port in connection.inputPorts) {
            if (![port.mediaType isEqualToString:AVMediaTypeVideo]) continue;
            if (![port.input isKindOfClass:AVCaptureDeviceInput.class]) continue;
            AVCaptureDevicePosition found = ((AVCaptureDeviceInput *)port.input).device.position;
            if (found == AVCaptureDevicePositionUnspecified) continue;
            if (position != AVCaptureDevicePositionUnspecified && position != found) return 0;
            position = found;
        }
    }
    if (position == AVCaptureDevicePositionBack) return BRPhotoRoleBack;
    if (position == AVCaptureDevicePositionFront) return BRPhotoRoleFront;
    return 0;
}

@interface BRReplacement : NSObject
@property(nonatomic,strong) BRSelectedPair *pair;
@property(nonatomic,strong) NSData *data;
@property(nonatomic) BRPhotoRole role;
@end
@implementation BRReplacement
@end

static void BRRememberCapture(AVCapturePhotoOutput *output, AVCapturePhotoSettings *settings, BRReplacement *selected) {
    @synchronized(output) {
        NSMutableDictionary *pending=objc_getAssociatedObject(output,BRPendingKey);
        if (!pending) { pending=[NSMutableDictionary new]; objc_setAssociatedObject(output,BRPendingKey,pending,OBJC_ASSOCIATION_RETAIN_NONATOMIC); }
        for (NSNumber *key in [pending.allKeys copy]) {
            BRReplacement *previous=pending[key];
            if ([previous.pair.expires compare:NSDate.date]!=NSOrderedDescending) [pending removeObjectForKey:key];
        }
        pending[@(settings.uniqueID)]=selected;
    }
}
static BRReplacement *BRTakeCapture(AVCapturePhotoOutput *output, int64_t uniqueID) {
    @synchronized(output) {
        NSMutableDictionary *pending=objc_getAssociatedObject(output,BRPendingKey);
        BRReplacement *selected=pending[@(uniqueID)]; [pending removeObjectForKey:@(uniqueID)]; return selected;
    }
}

static BOOL BRInstallPhotoGetter(Class cls) {
    @synchronized(BRHookLock) {
        NSString *name = NSStringFromClass(cls);
        if ([BRHookedPhotos containsObject:name]) return YES;
        SEL selector = @selector(fileDataRepresentation);
        Method method = class_getInstanceMethod(cls, selector);
        if (!BRMethodMatches(method, '@', 2)) return NO;
        NSData *(*original)(id,SEL) = (void *)method_getImplementation(method);
        IMP replacement = imp_implementationWithBlock(^NSData *(id photo) {
            BRReplacement *selected = objc_getAssociatedObject(photo, BRReplacementKey);
            if (!selected) return original(photo, selector);
            if ([BRState consume:selected.role pair:selected.pair]) BRStatus(@"写真2枚を反映済み");
            return selected.data;
        });
        // Install on the actual concrete class, including when it inherits the getter.
        class_replaceMethod(cls, selector, replacement, method_getTypeEncoding(method));
        [BRHookedPhotos addObject:name];
        return YES;
    }
}
static BOOL BRInstallDelegate(Class cls) {
    @synchronized(BRHookLock) {
        if (!BRKnownDelegate(cls)) return NO;
        NSString *name = NSStringFromClass(cls);
        if ([BRHookedDelegates containsObject:name]) return YES;
        SEL selector = @selector(captureOutput:didFinishProcessingPhoto:error:);
        Method method = class_getInstanceMethod(cls, selector);
        if (!BRMethodMatches(method, 'v', 5)) return NO;
        void (*original)(id,SEL,AVCapturePhotoOutput *,AVCapturePhoto *,NSError *) = (void *)method_getImplementation(method);
        IMP replacement = imp_implementationWithBlock(^(id delegate, AVCapturePhotoOutput *output, AVCapturePhoto *photo, NSError *error) {
            BRReplacement *selected = photo ? BRTakeCapture(output,photo.resolvedSettings.uniqueID) : nil;
            if (selected && photo && !error) {
                if (BRInstallPhotoGetter(object_getClass(photo))) {
                    objc_setAssociatedObject(photo, BRReplacementKey, selected, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                } else {
                    [BRState clear]; BRStatus(@"再選択してください");
                }
            }
            original(delegate, selector, output, photo, error);
        });
        class_replaceMethod(cls, selector, replacement, method_getTypeEncoding(method));
        SEL finishSelector=@selector(captureOutput:didFinishCaptureForResolvedSettings:error:);
        Method finishMethod=class_getInstanceMethod(cls,finishSelector);
        if (BRMethodMatches(finishMethod,'v',5)) {
            void (*finishOriginal)(id,SEL,AVCapturePhotoOutput *,AVCaptureResolvedPhotoSettings *,NSError *)=(void *)method_getImplementation(finishMethod);
            IMP finishReplacement=imp_implementationWithBlock(^(id delegate,AVCapturePhotoOutput *output,AVCaptureResolvedPhotoSettings *settings,NSError *error) {
                BRTakeCapture(output,settings.uniqueID);
                finishOriginal(delegate,finishSelector,output,settings,error);
            });
            class_replaceMethod(cls,finishSelector,finishReplacement,method_getTypeEncoding(finishMethod));
        }
        [BRHookedDelegates addObject:name];
        return YES;
    }
}
static BOOL BRInstallCaptureHook(void) {
    SEL selector = @selector(capturePhotoWithSettings:delegate:);
    Method method = class_getInstanceMethod(AVCapturePhotoOutput.class, selector);
    if (!BRMethodMatches(method, 'v', 4)) return NO;
    void (*original)(id,SEL,AVCapturePhotoSettings *,id<AVCapturePhotoCaptureDelegate>) = (void *)method_getImplementation(method);
    IMP replacement = imp_implementationWithBlock(^(AVCapturePhotoOutput *output, AVCapturePhotoSettings *settings, id<AVCapturePhotoCaptureDelegate> delegate) {
        BRSelectedPair *pair=[BRState currentAt:NSDate.date];
        if (pair) {
            BRPhotoRole role=BRRoleForOutput(output);
            if (role && BRInstallDelegate(object_getClass(delegate))) {
                BRReplacement *selected=[BRReplacement new]; selected.pair=pair; selected.role=role;
                selected.data=role==BRPhotoRoleBack?pair.back:pair.front;
                // This exact processor applies LeftMirrored to front-camera pixels.
                // Encode its inverse (the same transpose) only for this verified route.
                if (BRFrontCaptureNeedsCompensation(role==BRPhotoRoleFront,NSStringFromClass(object_getClass(delegate)).UTF8String)) {
                    selected.data=BRFrontProcessorData(selected.data);
                }
                if (selected.data) BRRememberCapture(output,settings,selected);
                else { [BRState clear]; BRStatus(@"読み込み失敗"); }
            } else {
                [BRState clear]; BRStatus(@"未対応のカメラ");
            }
        }
        original(output, selector, settings, delegate);
    });
    method_setImplementation(method, replacement);
    return YES;
}

static NSData *BRJPEG(UIImage *image) {
    if (!image || image.size.width<=0 || image.size.height<=0) return nil;
    CGFloat ratio = MIN(1.0, 2048.0/MAX(image.size.width,image.size.height));
    CGSize size = CGSizeMake(MAX(1,round(image.size.width*ratio)), MAX(1,round(image.size.height*ratio)));
    UIGraphicsImageRendererFormat *format = [UIGraphicsImageRendererFormat defaultFormat];
    format.scale = 1; format.opaque = YES;
    UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc] initWithSize:size format:format];
    // UIKit drawing applies UIImage orientation; encoded pixels are upright.
    return [renderer JPEGDataWithCompressionQuality:0.92 actions:^(UIGraphicsImageRendererContext *context) {
        [UIColor.blackColor setFill]; UIRectFill((CGRect){CGPointZero,size});
        [image drawInRect:(CGRect){CGPointZero,size}];
    }];
}

@interface BRAssignmentController : UIViewController
@property(nonatomic,strong) NSArray<UIImage *> *images;
@property(nonatomic,strong) UIImageView *backView;
@property(nonatomic,strong) UIImageView *frontView;
@property(nonatomic) BOOL swapped;
@property(nonatomic,copy) dispatch_block_t onDismiss;
@end
@implementation BRAssignmentController
- (void)viewDidLoad {
    [super viewDidLoad]; self.view.backgroundColor=UIColor.blackColor;
    UILabel *title=[UILabel new]; title.text=@"写真の割り当て"; title.font=[UIFont boldSystemFontOfSize:24]; title.textColor=UIColor.whiteColor;
    UILabel *backLabel=[UILabel new]; backLabel.text=@"背面カメラ"; backLabel.textColor=UIColor.whiteColor;
    UILabel *frontLabel=[UILabel new]; frontLabel.text=@"前面カメラ"; frontLabel.textColor=UIColor.whiteColor;
    self.backView=[[UIImageView alloc] initWithImage:self.images[0]];
    self.frontView=[[UIImageView alloc] initWithImage:self.images[1]];
    for (UIImageView *imageView in @[self.backView,self.frontView]) {
        imageView.contentMode=UIViewContentModeScaleAspectFit; imageView.backgroundColor=[UIColor colorWithWhite:0.1 alpha:1];
        [imageView.heightAnchor constraintEqualToConstant:180].active=YES;
    }
    UIButton *swap=[UIButton buttonWithType:UIButtonTypeSystem]; [swap setTitle:@"前面・背面を入れ替える" forState:UIControlStateNormal]; [swap addTarget:self action:@selector(swap) forControlEvents:UIControlEventTouchUpInside];
    UIButton *use=[UIButton buttonWithType:UIButtonTypeSystem]; [use setTitle:@"次の撮影に使う" forState:UIControlStateNormal]; use.titleLabel.font=[UIFont boldSystemFontOfSize:18]; [use addTarget:self action:@selector(use) forControlEvents:UIControlEventTouchUpInside];
    UIButton *cancel=[UIButton buttonWithType:UIButtonTypeSystem]; [cancel setTitle:@"キャンセル" forState:UIControlStateNormal]; [cancel addTarget:self action:@selector(cancel) forControlEvents:UIControlEventTouchUpInside];
    UIStackView *stack=[[UIStackView alloc] initWithArrangedSubviews:@[title,backLabel,self.backView,frontLabel,self.frontView,swap,use,cancel]];
    stack.axis=UILayoutConstraintAxisVertical; stack.spacing=12; stack.translatesAutoresizingMaskIntoConstraints=NO; [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[[stack.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:20],[stack.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:24],[stack.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-24]]];
}
- (void)swap { self.swapped=!self.swapped; self.backView.image=self.images[self.swapped?1:0]; self.frontView.image=self.images[self.swapped?0:1]; }
- (void)cancel { dispatch_block_t finished=self.onDismiss; self.onDismiss=nil; [self dismissViewControllerAnimated:YES completion:finished]; }
- (void)use {
    NSData *back=BRJPEG(self.backView.image), *front=BRJPEG(self.frontView.image);
    BRSelectedPair *pair=[[BRSelectedPair alloc] initWithBack:back front:front expires:[NSDate dateWithTimeIntervalSinceNow:180]];
    if (!pair) { BRStatus(@"読み込み失敗"); return; }
    [BRState arm:pair]; BRStatus(@"準備完了・撮影へ");
    dispatch_block_t finished=self.onDismiss; self.onDismiss=nil;
    [self dismissViewControllerAnimated:YES completion:finished];
}
@end

@class BRCameraRollUI;
@interface BRPhotoOverlayWindow : UIWindow
@property(nonatomic,weak) UIButton *photoButton;
@end
@implementation BRPhotoOverlayWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit=[super hitTest:point withEvent:event];
    return hit && self.photoButton && [hit isDescendantOfView:self.photoButton] ? hit : nil;
}
@end

@interface BRPhotoOverlayController : UIViewController
@property(nonatomic,weak) BRCameraRollUI *coordinator;
@end

@interface BRCameraRollUI : NSObject <PHPickerViewControllerDelegate,UIAdaptivePresentationControllerDelegate>
@property(nonatomic,strong) UIButton *button;
@property(nonatomic,strong) BRPhotoOverlayWindow *overlayWindow;
@property(nonatomic,strong) PHPickerViewController *picker;
@property(nonatomic,strong) BRAssignmentController *assignment;
@property(nonatomic,weak) UIWindow *selectionWindow;
@property(nonatomic,weak) UIWindowScene *selectionScene;
@property(nonatomic,weak) UIViewController *selectionPresenter;
@property(nonatomic,strong) NSDate *loadingDeadline;
@property(nonatomic,strong) NSDate *presentationDeadline;
@property(nonatomic,strong) NSMutableArray<NSProgress *> *pendingLoads;
@property(nonatomic,strong) NSArray<UIImage *> *pendingImages;
@property(nonatomic,strong) NSTimer *refreshTimer;
@property(nonatomic,strong) NSMutableArray *observers;
@property(nonatomic,copy) NSString *displayStatus;
@property(nonatomic) NSUInteger selectionGeneration;
@property(nonatomic) BOOL busy;
@property(nonatomic) BOOL attaching;
- (void)start;
- (void)attach;
- (UIWindow *)window;
- (UIViewController *)presenter;
- (void)layoutButton;
- (void)resetSelection;
- (void)abandonSelection;
- (void)presentAssignmentIfReady;
- (void)open;
@end

@implementation BRPhotoOverlayController
- (void)loadView { self.view=[UIView new]; self.view.backgroundColor=UIColor.clearColor; }
- (void)viewDidLayoutSubviews { [super viewDidLayoutSubviews]; [self.coordinator layoutButton]; }
- (UIInterfaceOrientationMask)supportedInterfaceOrientations { return UIInterfaceOrientationMaskAll; }
@end

@implementation BRCameraRollUI
- (void)dealloc {
    [self.refreshTimer invalidate];
    for (id observer in self.observers) [[NSNotificationCenter defaultCenter] removeObserver:observer];
}
- (void)start {
    if (self.refreshTimer) return;
    self.observers=[NSMutableArray new];
    __weak BRCameraRollUI *weakSelf=self;
    NSArray *names=@[UIApplicationDidBecomeActiveNotification,UIApplicationWillEnterForegroundNotification,
        UIApplicationWillResignActiveNotification,UIWindowDidBecomeKeyNotification,UIWindowDidBecomeVisibleNotification,
        UIWindowDidBecomeHiddenNotification,UISceneDidActivateNotification,UISceneWillDeactivateNotification,UISceneDidDisconnectNotification];
    for (NSString *name in names) {
        id observer=[[NSNotificationCenter defaultCenter] addObserverForName:name object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) {
            BRCameraRollUI *ui=weakSelf; if (!ui || note.object==ui.overlayWindow) return;
            if ([note.name isEqualToString:UISceneDidDisconnectNotification]) {
                if (note.object==ui.selectionScene) [ui abandonSelection];
                if (note.object==ui.overlayWindow.windowScene) { ui.overlayWindow.hidden=YES; ui.overlayWindow.rootViewController=nil; ui.overlayWindow=nil; }
            }
            if ([note.name isEqualToString:UIApplicationWillResignActiveNotification] ||
                ([note.name isEqualToString:UISceneWillDeactivateNotification] && note.object==ui.overlayWindow.windowScene)) {
                ui.overlayWindow.hidden=YES;
            } else [ui attach];
        }];
        [self.observers addObject:observer];
    }
    [self.observers addObject:[[NSNotificationCenter defaultCenter] addObserverForName:BRStatusNote object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) {
        BRCameraRollUI *ui=weakSelf; ui.displayStatus=note.userInfo[@"message"]; [ui attach];
    }]];
    self.refreshTimer=[NSTimer timerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *timer) { [weakSelf attach]; }];
    [[NSRunLoop mainRunLoop] addTimer:self.refreshTimer forMode:NSRunLoopCommonModes];
    [self attach];
}
- (UIWindow *)window {
    if (UIApplication.sharedApplication.applicationState!=UIApplicationStateActive) return nil;
    UIWindow *fallback=nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] || scene.activationState!=UISceneActivationStateForegroundActive) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if ([window isKindOfClass:BRPhotoOverlayWindow.class] || window.hidden || window.alpha<0.01 ||
                !window.rootViewController || window.windowLevel>=UIWindowLevelStatusBar) continue;
            if (window.isKeyWindow) return window;
            if (!fallback || window.windowLevel<fallback.windowLevel) fallback=window;
        }
    }
    return fallback;
}
- (UIViewController *)presenter {
    UIViewController *vc=[self window].rootViewController;
    while (vc.presentedViewController && !vc.presentedViewController.isBeingDismissed) vc=vc.presentedViewController;
    while (YES) {
        UIViewController *child=nil;
        if ([vc isKindOfClass:UINavigationController.class]) child=((UINavigationController *)vc).visibleViewController;
        else if ([vc isKindOfClass:UITabBarController.class]) child=((UITabBarController *)vc).selectedViewController;
        if (!child || child==vc) break;
        vc=child;
        while (vc.presentedViewController && !vc.presentedViewController.isBeingDismissed) vc=vc.presentedViewController;
    }
    return vc;
}
- (void)resetSelection {
    ++self.selectionGeneration;
    for (NSProgress *progress in self.pendingLoads) [progress cancel];
    self.pendingLoads=nil; self.pendingImages=nil; self.loadingDeadline=nil; self.presentationDeadline=nil;
    self.picker=nil; self.assignment.onDismiss=nil; self.assignment=nil;
    self.selectionWindow=nil; self.selectionScene=nil; self.selectionPresenter=nil; self.busy=NO;
}
- (void)abandonSelection {
    [self.picker dismissViewControllerAnimated:NO completion:nil];
    self.assignment.onDismiss=nil; [self.assignment dismissViewControllerAnimated:NO completion:nil];
    [self resetSelection];
}
- (void)layoutButton {
    UIView *view=self.overlayWindow.rootViewController.viewIfLoaded;
    if (!view || !self.button) return;
    UIEdgeInsets insets=view.safeAreaInsets;
    CGFloat width=MIN(190.0,MAX(0,CGRectGetWidth(view.bounds)-insets.left-insets.right-24));
    CGFloat top=MAX(insets.top+12,MIN(insets.top+72,CGRectGetHeight(view.bounds)-insets.bottom-56));
    self.button.frame=CGRectMake(insets.left+12,top,width,44);
}
- (void)presentAssignmentIfReady {
    if (!self.pendingImages) return;
    UIWindow *host=self.selectionWindow; UIViewController *presenter=self.selectionPresenter;
    if (!host || host.hidden || host.windowScene!=self.selectionScene || !presenter || presenter.viewIfLoaded.window!=host) {
        [self resetSelection]; BRStatus(@"画面変更・再選択"); return;
    }
    if (self.selectionScene.activationState!=UISceneActivationStateForegroundActive || UIApplication.sharedApplication.applicationState!=UIApplicationStateActive) return;
    if (presenter.isBeingPresented || presenter.isBeingDismissed || presenter.presentedViewController) return;
    BRAssignmentController *assignment=[BRAssignmentController new]; assignment.images=self.pendingImages;
    assignment.modalPresentationStyle=UIModalPresentationFullScreen; self.pendingImages=nil; self.loadingDeadline=nil;
    NSUInteger generation=self.selectionGeneration; __weak BRCameraRollUI *weakSelf=self;
    assignment.onDismiss=^{ BRCameraRollUI *ui=weakSelf; if (ui.selectionGeneration!=generation) return; [ui resetSelection]; [ui attach]; };
    self.assignment=assignment; self.presentationDeadline=[NSDate dateWithTimeIntervalSinceNow:3];
    [presenter presentViewController:assignment animated:YES completion:^{
        BRCameraRollUI *ui=weakSelf; if (ui.selectionGeneration!=generation) return;
        ui.presentationDeadline=nil; assignment.presentationController.delegate=ui; [ui attach];
    }];
}
- (void)attach {
    if (self.attaching) return;
    self.attaching=YES;
    @try {
        UIWindow *host=[self window];
        if (self.busy && self.selectionScene && (self.selectionScene.activationState==UISceneActivationStateUnattached ||
            !self.selectionWindow || self.selectionWindow.hidden || self.selectionWindow.windowScene!=self.selectionScene ||
            (host && host!=self.selectionWindow))) {
            [self abandonSelection]; self.displayStatus=@"画面変更・再選択";
        }
        if (self.loadingDeadline && [self.loadingDeadline compare:NSDate.date]!=NSOrderedDescending) {
            [self resetSelection]; self.displayStatus=@"読み込み期限・再選択";
        }
        UIViewController *owned=self.picker ?: self.assignment;
        if (self.busy && owned && !owned.presentingViewController && !owned.isBeingPresented && !owned.isBeingDismissed &&
            (!self.presentationDeadline || [self.presentationDeadline compare:NSDate.date]!=NSOrderedDescending)) {
            [self resetSelection]; self.displayStatus=@"写真を選択";
        }
        [self presentAssignmentIfReady];
        if (!host) { self.overlayWindow.hidden=YES; return; }
        if (self.overlayWindow && self.overlayWindow.windowScene!=host.windowScene) {
            self.overlayWindow.hidden=YES; self.overlayWindow.rootViewController=nil; self.overlayWindow=nil;
        }
        if (!self.button) {
            self.button=[UIButton buttonWithType:UIButtonTypeSystem];
            self.button.backgroundColor=[UIColor colorWithWhite:0.07 alpha:0.92]; self.button.layer.cornerRadius=14;
            [self.button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            self.button.titleLabel.font=[UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
            self.button.titleLabel.adjustsFontSizeToFitWidth=YES; self.button.titleLabel.minimumScaleFactor=0.7;
            self.button.accessibilityIdentifier=@"bereal493.photo-selection";
            [self.button addTarget:self action:@selector(open) forControlEvents:UIControlEventTouchUpInside];
            [self.button addGestureRecognizer:[[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(clear:)]];
        }
        if (!self.overlayWindow) {
            BRPhotoOverlayWindow *overlay=[[BRPhotoOverlayWindow alloc] initWithWindowScene:host.windowScene];
            BRPhotoOverlayController *controller=[BRPhotoOverlayController new]; controller.coordinator=self;
            overlay.backgroundColor=UIColor.clearColor; overlay.rootViewController=controller; overlay.photoButton=self.button;
            self.overlayWindow=overlay; [controller.view addSubview:self.button];
        }
        CGFloat highest=host.windowLevel;
        for (UIWindow *window in host.windowScene.windows) {
            if (![window isKindOfClass:BRPhotoOverlayWindow.class] && !window.hidden && window.rootViewController && window.windowLevel<UIWindowLevelStatusBar)
                highest=MAX(highest,window.windowLevel);
        }
        self.overlayWindow.windowLevel=MIN(UIWindowLevelStatusBar-1,highest+1);
        self.overlayWindow.frame=host.windowScene.coordinateSpace.bounds;
        self.overlayWindow.rootViewController.view.frame=self.overlayWindow.bounds;
        BOOL loading=self.loadingDeadline!=nil || self.pendingImages!=nil;
        [self.button setTitle:loading?@"読み込み中・タップで中止":(self.displayStatus?:@"写真を選択") forState:UIControlStateNormal];
        self.button.hidden=NO; self.button.enabled=YES; self.button.alpha=1;
        [self layoutButton];
        // Visibility never makes this window key. All touches outside the button pass through.
        self.overlayWindow.hidden=self.picker!=nil || self.assignment!=nil;
    } @finally { self.attaching=NO; }
}
- (void)clear:(UILongPressGestureRecognizer *)press {
    if (press.state!=UIGestureRecognizerStateBegan) return;
    if (self.loadingDeadline || self.pendingImages) [self resetSelection];
    [BRState clear]; self.displayStatus=@"写真を選択"; [self attach];
}
- (void)open {
    if (self.loadingDeadline || self.pendingImages) {
        [self resetSelection]; self.displayStatus=@"写真を選択"; [self attach]; return;
    }
    if (self.busy) return;
    UIWindow *host=[self window]; UIViewController *vc=[self presenter];
    if (!host || !vc || vc.viewIfLoaded.window!=host || vc.isBeingPresented || vc.isBeingDismissed || vc.presentedViewController) {
        self.displayStatus=@"画面切替中・再試行"; [self attach]; return;
    }
    [self resetSelection]; [BRState clear];
    PHPickerConfiguration *configuration=[[PHPickerConfiguration alloc] init]; configuration.filter=PHPickerFilter.imagesFilter;
    configuration.selectionLimit=2; configuration.selection=PHPickerConfigurationSelectionOrdered;
    PHPickerViewController *picker=[[PHPickerViewController alloc] initWithConfiguration:configuration]; picker.delegate=self;
    self.busy=YES; self.picker=picker; self.selectionWindow=host; self.selectionScene=host.windowScene; self.selectionPresenter=vc;
    self.presentationDeadline=[NSDate dateWithTimeIntervalSinceNow:3];
    NSUInteger generation=self.selectionGeneration; __weak BRCameraRollUI *weakSelf=self;
    [vc presentViewController:picker animated:YES completion:^{
        BRCameraRollUI *ui=weakSelf; if (ui.selectionGeneration!=generation) return;
        ui.presentationDeadline=nil; picker.presentationController.delegate=ui; [ui attach];
    }];
    [self attach];
}
- (void)presentationControllerDidDismiss:(UIPresentationController *)presentationController {
    UIViewController *controller=presentationController.presentedViewController;
    if (controller!=self.picker && controller!=self.assignment) return;
    [self resetSelection]; self.displayStatus=@"写真を選択"; [self attach];
}
- (void)picker:(PHPickerViewController *)picker didFinishPicking:(NSArray<PHPickerResult *> *)results {
    if (picker!=self.picker) return;
    NSUInteger generation=self.selectionGeneration; __weak BRCameraRollUI *weakSelf=self;
    [picker dismissViewControllerAnimated:YES completion:^{
        BRCameraRollUI *ui=weakSelf; if (!ui || ui.selectionGeneration!=generation) return;
        ui.picker=nil; ui.presentationDeadline=nil;
        if (results.count!=2) { [ui resetSelection]; [ui attach]; return; }
        ui.loadingDeadline=[NSDate dateWithTimeIntervalSinceNow:45]; ui.pendingLoads=[NSMutableArray new]; [ui attach];
        dispatch_group_t group=dispatch_group_create(); NSMutableArray *slots=[NSMutableArray arrayWithObjects:NSNull.null,NSNull.null,nil];
        [results enumerateObjectsUsingBlock:^(PHPickerResult *result, NSUInteger index, BOOL *stop) {
            if (![result.itemProvider canLoadObjectOfClass:UIImage.class]) return;
            dispatch_group_enter(group); __block BOOL completed=NO;
            NSProgress *progress=[result.itemProvider loadObjectOfClass:UIImage.class completionHandler:^(id<NSItemProviderReading> object, NSError *error) {
                @synchronized(slots) {
                    if (completed) return; completed=YES;
                    if ([object isKindOfClass:UIImage.class]) slots[index]=object;
                }
                dispatch_group_leave(group);
            }];
            if (progress) [ui.pendingLoads addObject:progress];
        }];
        dispatch_group_notify(group,dispatch_get_main_queue(),^{
            BRCameraRollUI *current=weakSelf; if (!current || current.selectionGeneration!=generation) return;
            current.pendingLoads=nil;
            if (![slots[0] isKindOfClass:UIImage.class] || ![slots[1] isKindOfClass:UIImage.class]) {
                [current resetSelection]; BRStatus(@"読み込み失敗"); [current attach]; return;
            }
            current.pendingImages=[slots copy];
            // Keep a deadline until the captured presenter can actually accept the assignment.
            [current attach];
        });
    }];
}
@end

__attribute__((constructor)) static void BRCameraRollInit(void) {
    NSDictionary *info=NSBundle.mainBundle.infoDictionary;
    if (![info[@"CFBundleShortVersionString"] isEqual:@"4.93.0"] || ![info[@"CFBundleVersion"] isEqual:@"23026"]) return;
    BRInstallSandboxGroupFallback();
    BRState=[BRPairState new]; BRHookLock=[NSObject new]; BRHookedDelegates=[NSMutableSet new]; BRHookedPhotos=[NSMutableSet new];
    if (!BRInstallCaptureHook()) return;
    dispatch_async(dispatch_get_main_queue(),^{
        static BRCameraRollUI *ui; ui=[BRCameraRollUI new];
        [ui start];
    });
}
