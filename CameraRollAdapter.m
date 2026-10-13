#import <UIKit/UIKit.h>
#import <PhotosUI/PhotosUI.h>
#import <AVFoundation/AVFoundation.h>
#import <objc/runtime.h>
#import "BRPairState.h"

static BRPairState *BRState;
static const void *BRReplacementKey = &BRReplacementKey;
static const void *BRPendingKey = &BRPendingKey;
static NSMutableSet<NSString *> *BRHookedDelegates;
static NSMutableSet<NSString *> *BRHookedPhotos;
static NSObject *BRHookLock;
static NSString *const BRStatusNote = @"BRCameraRollStatus";
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
    if (![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.ayato.bereal493"]) return;
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
                BRRememberCapture(output,settings,selected);
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
- (void)cancel { [self dismissViewControllerAnimated:YES completion:nil]; }
- (void)use {
    NSData *back=BRJPEG(self.backView.image), *front=BRJPEG(self.frontView.image);
    BRSelectedPair *pair=[[BRSelectedPair alloc] initWithBack:back front:front expires:[NSDate dateWithTimeIntervalSinceNow:180]];
    if (!pair) { BRStatus(@"読み込み失敗"); return; }
    [BRState arm:pair]; BRStatus(@"準備完了・撮影へ");
    [self dismissViewControllerAnimated:YES completion:nil];
}
@end

@interface BRCameraRollUI : NSObject <PHPickerViewControllerDelegate>
@property(nonatomic,strong) UIButton *button;
@property(nonatomic) BOOL busy;
- (void)attach;
@end
@implementation BRCameraRollUI
- (UIWindow *)window {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] || scene.activationState!=UISceneActivationStateForegroundActive) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) if (window.isKeyWindow) return window;
    }
    return nil;
}
- (UIViewController *)presenter {
    UIViewController *vc=[self window].rootViewController;
    while (vc.presentedViewController && !vc.presentedViewController.isBeingDismissed) vc=vc.presentedViewController;
    return vc;
}
- (void)attach {
    UIWindow *window=[self window]; if (!window) return;
    if (!self.button) {
        self.button=[UIButton buttonWithType:UIButtonTypeSystem];
        self.button.backgroundColor=[UIColor colorWithWhite:0.07 alpha:0.92]; self.button.layer.cornerRadius=14;
        [self.button setTitle:@"写真を選択" forState:UIControlStateNormal]; [self.button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
        self.button.titleLabel.font=[UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
        [self.button addTarget:self action:@selector(open) forControlEvents:UIControlEventTouchUpInside];
        UILongPressGestureRecognizer *press=[[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(clear:)]; [self.button addGestureRecognizer:press];
    }
    if (self.button.superview!=window) { [window addSubview:self.button]; self.button.frame=CGRectMake(12,window.safeAreaInsets.top+72,142,44); }
    [window bringSubviewToFront:self.button];
}
- (void)clear:(UILongPressGestureRecognizer *)press { if (press.state==UIGestureRecognizerStateBegan) { [BRState clear]; [self.button setTitle:@"写真を選択" forState:UIControlStateNormal]; } }
- (void)open {
    if (self.busy) return; UIViewController *vc=[self presenter]; if (!vc) return;
    [BRState clear];
    PHPickerConfiguration *configuration=[[PHPickerConfiguration alloc] init]; configuration.filter=PHPickerFilter.imagesFilter;
    configuration.selectionLimit=2; configuration.selection=PHPickerConfigurationSelectionOrdered;
    PHPickerViewController *picker=[[PHPickerViewController alloc] initWithConfiguration:configuration]; picker.delegate=self;
    self.busy=YES; [vc presentViewController:picker animated:YES completion:nil];
}
- (void)picker:(PHPickerViewController *)picker didFinishPicking:(NSArray<PHPickerResult *> *)results {
    [picker dismissViewControllerAnimated:YES completion:^{
        if (results.count!=2) { self.busy=NO; return; }
        dispatch_group_t group=dispatch_group_create(); NSMutableArray *slots=[NSMutableArray arrayWithObjects:NSNull.null,NSNull.null,nil];
        [results enumerateObjectsUsingBlock:^(PHPickerResult *result, NSUInteger index, BOOL *stop) {
            if (![result.itemProvider canLoadObjectOfClass:UIImage.class]) return;
            dispatch_group_enter(group);
            [result.itemProvider loadObjectOfClass:UIImage.class completionHandler:^(id<NSItemProviderReading> object, NSError *error) {
                @synchronized(slots) { if ([object isKindOfClass:UIImage.class]) slots[index]=object; }
                dispatch_group_leave(group);
            }];
        }];
        dispatch_group_notify(group,dispatch_get_main_queue(),^{
            self.busy=NO;
            if (![slots[0] isKindOfClass:UIImage.class] || ![slots[1] isKindOfClass:UIImage.class]) { BRStatus(@"読み込み失敗"); return; }
            BRAssignmentController *assignment=[BRAssignmentController new]; assignment.images=[slots copy]; assignment.modalPresentationStyle=UIModalPresentationFullScreen;
            [[self presenter] presentViewController:assignment animated:YES completion:nil];
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
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) { [ui attach]; }];
        [[NSNotificationCenter defaultCenter] addObserverForName:BRStatusNote object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) { [ui.button setTitle:note.userInfo[@"message"] forState:UIControlStateNormal]; }];
        [ui attach];
    });
}
