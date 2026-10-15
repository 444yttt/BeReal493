// A synthetic app executes the actual production UI under UIKit/UIScene.
// The fixture's 0/0 bundle version skips the capture-hook constructor.
// No original app, user images, signing assets, or private APIs are used.
#import "../CameraRollAdapter.m"

static NSString *const BRFixtureSuite = @"bereal493-real-uikit-lifecycle-v1";

// Override only the presenter dependency to exercise rejected presentations;
// all selection, lifecycle, and window behavior stays in the production class.
@interface BRFixtureUI : BRCameraRollUI
@property(nonatomic) BOOL forcePresenter;
@property(nonatomic, strong) UIViewController *fixturePresenter;
@end
@implementation BRFixtureUI
- (UIViewController *)presenter { return self.forcePresenter ? self.fixturePresenter : [super presenter]; }
@end

@interface BRFixtureProvider : NSItemProvider
@property(nonatomic, copy) void (^held)(id<NSItemProviderReading>, NSError *);
@property(nonatomic) BOOL fail;
- (void)complete:(UIImage *)image;
@end
@implementation BRFixtureProvider
- (BOOL)canLoadObjectOfClass:(Class<NSItemProviderReading>)type { return type == UIImage.class; }
- (NSProgress *)loadObjectOfClass:(Class<NSItemProviderReading>)type completionHandler:(void (^)(id<NSItemProviderReading>, NSError *))completion {
    self.held = completion;
    if (self.fail) dispatch_async(dispatch_get_main_queue(), ^{
        if (self.held) self.held(nil, [NSError errorWithDomain:@"BRUIFixture" code:1 userInfo:nil]);
        self.held = nil;
    });
    return [NSProgress progressWithTotalUnitCount:1];
}
- (void)complete:(UIImage *)image {
    if (self.held) self.held(image, nil);
    self.held = nil;
}
@end

@interface BRFixtureResult : NSObject
@property(nonatomic, strong) NSItemProvider *itemProvider;
@end
@implementation BRFixtureResult
@end

@interface BRUIFixture : NSObject
@property(nonatomic, strong) UIWindowScene *scene;
@property(nonatomic, strong) UIWindow *firstWindow;
@property(nonatomic, strong) UIWindow *secondWindow;
@property(nonatomic, strong) BRCameraRollUI *ui;
@property(nonatomic, strong) NSMutableArray<NSDictionary *> *checks;
@property(nonatomic, copy) NSString *nonce;
@property(nonatomic) BOOL finished;
@property(nonatomic) BOOL awaitingResume;
@property(nonatomic) BOOL backgroundObserved;
- (void)begin;
- (void)background;
- (void)resume;
@end

#define CHECK(condition, label) do { if (![self check:(condition) name:(label)]) return; } while (0)

@implementation BRUIFixture
- (NSURL *)file:(NSString *)name {
    NSURL *documents = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].firstObject;
    [NSFileManager.defaultManager createDirectoryAtURL:documents withIntermediateDirectories:YES attributes:nil error:nil];
    return [documents URLByAppendingPathComponent:name];
}
- (void)write:(NSDictionary *)value name:(NSString *)name {
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingPrettyPrinted error:nil];
    [data writeToURL:[self file:name] options:NSDataWritingAtomic error:nil];
}
- (void)finish:(BOOL)passed {
    if (self.finished) return;
    self.finished = YES;
    [self write:@{@"suite":BRFixtureSuite, @"nonce":self.nonce ?: @"missing", @"passed":@(passed),
                  @"checks":self.checks ?: @[],
                  @"limitations":@[@"Synthetic UIKit app; no BeReal navigation, real camera, or HID-tap injection tested.",
                                    @"Hit testing is real UIKit; cross-scene disconnect/reconnect is not simulated."]}
             name:@"ui-lifecycle-result.json"];
    NSLog(@"UIKit lifecycle fixture %@", passed ? @"PASS" : @"FAIL");
}
- (BOOL)check:(BOOL)condition name:(NSString *)name {
    if (self.finished) return NO;
    [self.checks addObject:@{@"name":name, @"passed":@(condition)}];
    NSLog(@"UIKit fixture %@: %@", condition ? @"PASS" : @"FAIL", name);
    if (!condition) [self finish:NO];
    return condition;
}
- (void)wait:(NSString *)name until:(BOOL (^)(void))condition next:(void (^)(void))next {
    [self wait:name deadline:[NSDate dateWithTimeIntervalSinceNow:5] until:condition next:next];
}
- (void)wait:(NSString *)name deadline:(NSDate *)deadline until:(BOOL (^)(void))condition next:(void (^)(void))next {
    if (self.finished) return;
    if (condition()) { next(); return; }
    if (deadline.timeIntervalSinceNow <= 0) { [self check:NO name:[name stringByAppendingString:@"_timeout"]]; return; }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 25 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        [self wait:name deadline:deadline until:condition next:next];
    });
}
- (BOOL)visible {
    return self.ui.overlayWindow && !self.ui.overlayWindow.hidden && !self.ui.button.hidden
        && self.ui.button.alpha > 0 && self.ui.button.window == self.ui.overlayWindow;
}
- (UIImage *)image {
    UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(20, 30)];
    return [renderer imageWithActions:^(UIGraphicsImageRendererContext *context) {
        [UIColor.greenColor setFill]; UIRectFill(CGRectMake(0, 0, 20, 30));
    }];
}
- (NSArray<PHPickerResult *> *)results:(NSArray<BRFixtureProvider *> *)providers {
    NSMutableArray *results = [NSMutableArray new];
    for (BRFixtureProvider *provider in providers) {
        BRFixtureResult *result = [BRFixtureResult new]; result.itemProvider = provider; [results addObject:result];
    }
    return (NSArray<PHPickerResult *> *)results;
}
- (void)begin {
    self.checks = [NSMutableArray new];
    self.nonce = NSProcessInfo.processInfo.environment[@"BRUI_TEST_NONCE"];
    CHECK(self.nonce.length == 32, @"host_nonce_present");
    BRState = [BRPairState new];
    [UIView setAnimationsEnabled:NO];
    self.ui = [BRFixtureUI new];
    [self.ui start];
    [self.ui attach];
    [self wait:@"initial_overlay" until:^BOOL{ return [self visible]; } next:^{ [self windowChecks]; }];
}
- (void)windowChecks {
    UIWindow *overlay = self.ui.overlayWindow;
    CHECK([self visible] && !overlay.isKeyWindow && self.firstWindow.isKeyWindow
          && overlay.windowScene == self.scene, @"visible_non_key_overlay");
    CGPoint inside = [self.ui.button convertPoint:CGPointMake(CGRectGetMidX(self.ui.button.bounds), CGRectGetMidY(self.ui.button.bounds)) toView:overlay];
    UIView *hit = [overlay hitTest:inside withEvent:nil];
    CHECK(hit == self.ui.button || [hit isDescendantOfView:self.ui.button], @"inside_button_hit");
    CGPoint outside = CGPointMake(CGRectGetMaxX(overlay.bounds) - 2, CGRectGetMaxY(overlay.bounds) - 2);
    CHECK([overlay hitTest:outside withEvent:nil] == nil, @"outside_button_passthrough");
    UIView *cover = [[UIView alloc] initWithFrame:self.firstWindow.bounds]; cover.backgroundColor = UIColor.redColor;
    [self.firstWindow addSubview:cover]; [self.firstWindow bringSubviewToFront:cover];
    CHECK([self visible] && overlay.windowLevel > self.firstWindow.windowLevel
          && self.ui.button.window == overlay, @"app_subview_cannot_cover_overlay");
    [cover removeFromSuperview];
    CGRect originalBounds = overlay.bounds;
    overlay.bounds = CGRectMake(0, 0, 320, 260);
    [overlay setNeedsLayout]; [overlay layoutIfNeeded];
    [overlay.rootViewController.view setNeedsLayout]; [overlay.rootViewController.view layoutIfNeeded];
    [self.ui layoutButton];
    CGRect button = [self.ui.button convertRect:self.ui.button.bounds toView:overlay];
    CHECK(CGRectContainsRect(overlay.bounds, button) && button.size.width >= 44 && button.size.height >= 44,
          @"same_window_relayout");
    overlay.rootViewController.additionalSafeAreaInsets = UIEdgeInsetsMake(27, 19, 21, 13);
    [overlay.rootViewController.view setNeedsLayout]; [overlay.rootViewController.view layoutIfNeeded];
    [self.ui layoutButton];
    UIView *overlayView = overlay.rootViewController.view;
    CGRect safe = UIEdgeInsetsInsetRect(overlayView.bounds, overlayView.safeAreaInsets);
    CHECK(CGRectContainsRect(safe, [self.ui.button convertRect:self.ui.button.bounds toView:overlayView]),
          @"safe_area_relayout");
    overlay.rootViewController.additionalSafeAreaInsets = UIEdgeInsetsZero;
    overlay.bounds = originalBounds;
    [self.ui layoutButton];
    self.firstWindow.rootViewController = [UIViewController new];
    [self.firstWindow.rootViewController loadViewIfNeeded];
    [self.ui attach];
    CHECK([self visible] && self.ui.button.window == overlay, @"root_controller_replacement");
    self.secondWindow = [[UIWindow alloc] initWithWindowScene:self.scene];
    self.secondWindow.rootViewController = [UIViewController new];
    self.secondWindow.rootViewController.view.backgroundColor = UIColor.blueColor;
    [self.secondWindow makeKeyAndVisible];
    [self wait:@"switch_key_window" until:^BOOL{ return [self.ui window] == self.secondWindow; } next:^{
        CHECK(self.secondWindow.isKeyWindow && !self.ui.overlayWindow.isKeyWindow && [self visible], @"key_window_switch");
        NSUInteger count = 0;
        for (UIWindow *window in self.scene.windows)
            if ([window isKindOfClass:BRPhotoOverlayWindow.class] && !window.hidden) ++count;
        CHECK(count == 1, @"single_visible_overlay");
        [self failedPresenter];
    }];
}
- (void)failedPresenter {
    BRFixtureUI *ui = (BRFixtureUI *)self.ui;
    ui.forcePresenter = YES;
    ui.fixturePresenter = [UIViewController new]; [ui.fixturePresenter loadViewIfNeeded];
    [ui open];
    CHECK(!ui.busy && !ui.picker && [self visible], @"detached_presenter_recovers");
    ui.fixturePresenter = nil;
    [ui open];
    CHECK(!ui.busy && !ui.picker && [self visible], @"nil_presenter_recovers");
    ui.forcePresenter = NO;
    [self busyWindowSwitch];
}
- (void)busyWindowSwitch {
    [self withPicker:^(PHPickerViewController *picker) {
        BRFixtureProvider *one = [BRFixtureProvider new], *two = [BRFixtureProvider new];
        [self.ui picker:picker didFinishPicking:[self results:@[one,two]]];
        [self wait:@"busy_window_load_started" until:^BOOL{ return self.ui.pendingLoads.count > 0 && [self visible]; } next:^{
            [self.firstWindow makeKeyAndVisible];
            [self wait:@"busy_window_switched" until:^BOOL{ return !self.ui.busy && [self.ui window] == self.firstWindow; } next:^{
                [one complete:[self image]]; [two complete:[self image]];
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
                    CHECK(!self.ui.assignment && !self.ui.picker && !self.ui.busy && [self visible], @"busy_key_window_switch_recovers");
                    [self.secondWindow makeKeyAndVisible];
                    [self wait:@"busy_window_restore" until:^BOOL{ return [self.ui window] == self.secondWindow; } next:^{
                        [self unownedModal];
                    }];
                });
            }];
        }];
    }];
}
- (void)unownedModal {
    UIViewController *modal = [UIViewController new]; modal.modalPresentationStyle = UIModalPresentationFullScreen;
    modal.view.backgroundColor = UIColor.orangeColor;
    [self.secondWindow.rootViewController presentViewController:modal animated:NO completion:^{
        [self.ui attach];
        CHECK([self.ui presenter] == modal && [self visible], @"unowned_modal_does_not_remove_button");
        [modal dismissViewControllerAnimated:NO completion:^{ [self pickerCancel]; }];
    }];
}
- (void)withPicker:(void (^)(PHPickerViewController *))next {
    [self.ui open];
    [self wait:@"picker_presented" until:^BOOL{
        return self.ui.picker.presentingViewController != nil && !self.ui.picker.isBeingPresented && !self.ui.picker.isBeingDismissed;
    } next:^{
        CHECK(self.ui.busy && ![self visible], @"owned_picker_hides_overlay");
        next(self.ui.picker);
    }];
}
- (void)pickerCancel {
    [self withPicker:^(PHPickerViewController *picker) {
        [self.ui picker:picker didFinishPicking:@[]];
        [self wait:@"picker_cancel" until:^BOOL{ return !self.ui.busy && [self visible]; } next:^{
            CHECK(!self.ui.picker && !self.ui.assignment, @"picker_cancel_recovers");
            [self loadingCancel];
        }];
    }];
}
- (void)loadingCancel {
    [self withPicker:^(PHPickerViewController *picker) {
        BRFixtureProvider *one = [BRFixtureProvider new], *two = [BRFixtureProvider new];
        [self.ui picker:picker didFinishPicking:[self results:@[one,two]]];
        [self wait:@"loading_visible" until:^BOOL{ return self.ui.pendingLoads.count > 0 && [self visible]; } next:^{
            NSUInteger generation = self.ui.selectionGeneration;
            [self.ui open];
            CHECK(!self.ui.busy && self.ui.selectionGeneration != generation, @"loading_cancel_resets_busy");
            [one complete:[self image]]; [two complete:[self image]];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
                CHECK(!self.ui.assignment && !self.ui.busy && [self visible], @"loading_cancel_ignores_late_results");
                [self loadingFailure];
            });
        }];
    }];
}
- (void)loadingFailure {
    [self withPicker:^(PHPickerViewController *picker) {
        BRFixtureProvider *one = [BRFixtureProvider new], *two = [BRFixtureProvider new]; one.fail = YES; two.fail = YES;
        [self.ui picker:picker didFinishPicking:[self results:@[one,two]]];
        [self wait:@"provider_failure" until:^BOOL{ return !self.ui.busy && [self visible]; } next:^{
            CHECK(!self.ui.assignment && !self.ui.picker, @"loading_failure_recovers");
            [self loadingTimeout];
        }];
    }];
}
- (void)loadingTimeout {
    [self withPicker:^(PHPickerViewController *picker) {
        BRFixtureProvider *one = [BRFixtureProvider new], *two = [BRFixtureProvider new];
        [self.ui picker:picker didFinishPicking:[self results:@[one,two]]];
        [self wait:@"provider_timeout_started" until:^BOOL{ return self.ui.pendingLoads.count > 0 && [self visible]; } next:^{
            self.ui.loadingDeadline = [NSDate dateWithTimeIntervalSinceNow:-1];
            [self.ui attach];
            [self wait:@"provider_timeout" until:^BOOL{ return !self.ui.busy && [self visible]; } next:^{
                CHECK(!self.ui.assignment && self.ui.pendingLoads.count == 0, @"loading_timeout_recovers");
                [one complete:[self image]]; [two complete:[self image]];
                [self assignment:NO];
            }];
        }];
    }];
}
- (void)assignment:(BOOL)use {
    [self withPicker:^(PHPickerViewController *picker) {
        BRFixtureProvider *one = [BRFixtureProvider new], *two = [BRFixtureProvider new];
        [self.ui picker:picker didFinishPicking:[self results:@[one,two]]];
        [self wait:@"assignment_load_started" until:^BOOL{ return one.held && two.held; } next:^{
            [one complete:[self image]]; [two complete:[self image]];
            [self wait:@"assignment_presented" until:^BOOL{
                return self.ui.assignment.presentingViewController != nil && !self.ui.assignment.isBeingPresented;
            } next:^{
                CHECK(self.ui.busy && ![self visible], @"owned_assignment_hides_overlay");
                CHECK(!self.ui.loadingDeadline, @"assignment_has_no_loading_deadline");
                if (use) [self.ui.assignment use]; else [self.ui.assignment cancel];
                [self wait:@"assignment_dismissed" until:^BOOL{ return !self.ui.busy && [self visible]; } next:^{
                    CHECK(!self.ui.assignment && !self.ui.picker,
                          use ? @"assignment_use_recovers" : @"assignment_cancel_recovers");
                    if (use) {
                        CHECK([BRState currentAt:NSDate.date] != nil, @"assignment_use_arms_pair");
                        [self requestBackground];
                    } else {
                        CHECK([BRState currentAt:NSDate.date] == nil, @"assignment_cancel_does_not_arm_pair");
                        [self assignment:YES];
                    }
                }];
            }];
        }];
    }];
}
- (void)requestBackground {
    self.awaitingResume = YES;
    [self write:@{@"nonce":self.nonce, @"phase":@"waiting-background"} name:@"ui-lifecycle-phase.json"];
}
- (void)background {
    if (!self.awaitingResume || self.finished) return;
    self.backgroundObserved = YES;
    [self write:@{@"nonce":self.nonce, @"phase":@"backgrounded"} name:@"ui-lifecycle-phase.json"];
}
- (void)resume {
    if (!self.awaitingResume || !self.backgroundObserved || self.finished) return;
    self.awaitingResume = NO;
    CHECK(self.backgroundObserved, @"real_background_observed");
    [self wait:@"resume_overlay" until:^BOOL{ return [self visible]; } next:^{
        CHECK(self.secondWindow.isKeyWindow && !self.ui.overlayWindow.isKeyWindow
              && !self.ui.busy && [self.ui window] == self.secondWindow, @"real_resume_recovers");
        [self finish:YES];
    }];
}
@end

static BRUIFixture *BRFixture;

static void BRFixtureException(NSException *exception) {
    // Emit only a fixed failure checkpoint, never exception reasons/stack data.
    if (!BRFixture) {
        BRFixture = [BRUIFixture new];
        BRFixture.checks = [NSMutableArray new];
        BRFixture.nonce = NSProcessInfo.processInfo.environment[@"BRUI_TEST_NONCE"];
    }
    [BRFixture check:NO name:@"uncaught_uikit_exception"];
}

@interface BRUIFixtureSceneDelegate : NSObject <UIWindowSceneDelegate>
@property(nonatomic, strong) UIWindow *window;
@end
@implementation BRUIFixtureSceneDelegate
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)options {
    if (![scene isKindOfClass:UIWindowScene.class]) return;
    self.window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
    self.window.rootViewController = [UIViewController new];
    self.window.rootViewController.view.backgroundColor = UIColor.whiteColor;
    [self.window makeKeyAndVisible];
    BRFixture = [BRUIFixture new]; BRFixture.scene = (UIWindowScene *)scene; BRFixture.firstWindow = self.window;
}
- (void)sceneDidBecomeActive:(UIScene *)scene {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!BRFixture.ui && !BRFixture.finished) [BRFixture begin];
        else [BRFixture resume];
    });
}
- (void)sceneDidEnterBackground:(UIScene *)scene { [BRFixture background]; }
@end

@interface BRUIFixtureAppDelegate : NSObject <UIApplicationDelegate>
@end
@implementation BRUIFixtureAppDelegate
@end

int main(int argc, char **argv) {
    @autoreleasepool {
        NSSetUncaughtExceptionHandler(BRFixtureException);
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(BRUIFixtureAppDelegate.class));
    }
}
