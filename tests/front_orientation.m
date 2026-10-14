#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import "../BRFrontOrientation.h"

static void require(BOOL condition, NSString *message) {
    if (!condition) { NSLog(@"FAIL: %@", message); exit(1); }
}

static CGContextRef RGBContext(size_t width, size_t height, void *pixels) {
    CGColorSpaceRef space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    require(space != NULL, @"sRGB color space");
    CGContextRef context = CGBitmapContextCreate(pixels, width, height, 8, width * 4,
        space, kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(space);
    require(context != NULL, @"RGB bitmap context");
    return context;
}

static CGImageRef Fixture(size_t width, size_t height) {
    CGContextRef context = RGBContext(width, height, NULL);
    unsigned char *pixels = CGBitmapContextGetData(context);
    require(pixels != NULL, @"fixture pixel storage");
    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            unsigned char *p = pixels + 4 * (y * width + x);
            p[0] = (unsigned char)((x * 37 + y * 19 + 11) & 255);
            p[1] = (unsigned char)((x * 13 + y * 71 + 23) & 255);
            p[2] = (unsigned char)((x * 83 + y * 29 + 47) & 255);
            p[3] = 255;
        }
    }
    // Four distinct corners expose a mirror, crop or quarter-turn error.
    const unsigned char corners[4][4] = {
        {255, 0, 0, 255}, {0, 255, 0, 255},
        {0, 0, 255, 255}, {255, 255, 0, 255},
    };
    const size_t positions[4] = {0, width - 1, (height - 1) * width, height * width - 1};
    for (size_t i = 0; i < 4; i++) memcpy(pixels + 4 * positions[i], corners[i], 4);
    CGImageRef image = CGBitmapContextCreateImage(context);
    CGContextRelease(context);
    require(image != NULL, @"fixture CGImage");
    return image;
}

static NSData *RGBPixels(CGImageRef image) {
    const size_t width = CGImageGetWidth(image), height = CGImageGetHeight(image);
    NSMutableData *pixels = [NSMutableData dataWithLength:width * height * 4];
    CGContextRef context = RGBContext(width, height, pixels.mutableBytes);
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextSetInterpolationQuality(context, kCGInterpolationNone);
    CGContextSetShouldAntialias(context, false);
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
    CGContextRelease(context);
    return pixels;
}

// Independent Apple ImageIO oracle: tag lossless TIFF with EXIF 5, then ask
// ImageIO to materialize the tagged transform. No helper matrix is used here.
static CGImageRef ImageIOExif5(CGImageRef image) {
    NSMutableData *encoded = [NSMutableData data];
    CGImageDestinationRef destination = CGImageDestinationCreateWithData(
        (__bridge CFMutableDataRef)encoded, CFSTR("public.tiff"), 1, NULL);
    require(destination != NULL, @"TIFF destination");
    NSDictionary *properties = @{
        (__bridge NSString *)kCGImagePropertyOrientation: @5,
        (__bridge NSString *)kCGImagePropertyTIFFDictionary: @{
            (__bridge NSString *)kCGImagePropertyTIFFOrientation: @5,
            (__bridge NSString *)kCGImagePropertyTIFFCompression: @1,
        },
    };
    CGImageDestinationAddImage(destination, image, (__bridge CFDictionaryRef)properties);
    BOOL finalized = CGImageDestinationFinalize(destination);
    CFRelease(destination);
    require(finalized, @"lossless TIFF encoding");

    CGImageSourceRef source = CGImageSourceCreateWithData((__bridge CFDataRef)encoded, NULL);
    require(source != NULL, @"TIFF source");
    CFDictionaryRef rawProperties = CGImageSourceCopyPropertiesAtIndex(source, 0, NULL);
    NSDictionary *readback = (__bridge NSDictionary *)rawProperties;
    require([readback[(__bridge NSString *)kCGImagePropertyOrientation] integerValue] == 5,
            @"TIFF retained EXIF orientation 5");
    if (rawProperties) CFRelease(rawProperties);
    NSDictionary *options = @{
        (__bridge NSString *)kCGImageSourceCreateThumbnailFromImageAlways: @YES,
        (__bridge NSString *)kCGImageSourceCreateThumbnailWithTransform: @YES,
        (__bridge NSString *)kCGImageSourceThumbnailMaxPixelSize:
            @(MAX(CGImageGetWidth(image), CGImageGetHeight(image))),
        (__bridge NSString *)kCGImageSourceShouldCacheImmediately: @YES,
    };
    CGImageRef result = CGImageSourceCreateThumbnailAtIndex(source, 0, (__bridge CFDictionaryRef)options);
    CFRelease(source);
    require(result != NULL, @"ImageIO transformed thumbnail");
    return result;
}

static void CompareFixture(size_t width, size_t height, NSString *label) {
    CGImageRef original = Fixture(width, height);
    CGImageRef transformed = BRCreateLeftMirroredPixels(original);
    require(transformed != NULL, [label stringByAppendingString:@" transformed image"]);
    require(CGImageGetWidth(transformed) == height && CGImageGetHeight(transformed) == width,
            [label stringByAppendingString:@" width/height swapped"]);
    CGImageRef oracle = ImageIOExif5(original);
    require(CGImageGetWidth(oracle) == height && CGImageGetHeight(oracle) == width,
            [label stringByAppendingString:@" oracle width/height swapped"]);
    NSData *actualPixels = RGBPixels(transformed), *oraclePixels = RGBPixels(oracle);
    require([actualPixels isEqual:oraclePixels],
            [label stringByAppendingString:@" every pixel matches independent EXIF 5 oracle"]);
    // Explicitly check all corners as well as the asymmetric interior above.
    const size_t corners[4] = {0, height - 1, (width - 1) * height, width * height - 1};
    for (size_t i = 0; i < 4; i++) {
        require(memcmp((const unsigned char *)actualPixels.bytes + 4 * corners[i],
                       (const unsigned char *)oraclePixels.bytes + 4 * corners[i], 4) == 0,
                [label stringByAppendingString:@" four corner colors match"]);
    }
    CGImageRef restored = BRCreateLeftMirroredPixels(transformed);
    require(restored != NULL && CGImageGetWidth(restored) == width && CGImageGetHeight(restored) == height,
            [label stringByAppendingString:@" self-inverse dimensions"]);
    require([RGBPixels(restored) isEqual:RGBPixels(original)],
            [label stringByAppendingString:@" self-inverse exact pixel roundtrip"]);
    CGImageRelease(restored);
    CGImageRelease(oracle);
    CGImageRelease(transformed);
    CGImageRelease(original);
}

static void GuardTests(void) {
    require(BRCreateLeftMirroredPixels(NULL) == NULL, @"nil image rejected");
    CGImageRef tooWide = Fixture(2049, 1), tooTall = Fixture(1, 2049);
    require(BRCreateLeftMirroredPixels(tooWide) == NULL, @"unnormalized width rejected");
    require(BRCreateLeftMirroredPixels(tooTall) == NULL, @"unnormalized height rejected");
    CGImageRelease(tooWide); CGImageRelease(tooTall);
    CGImageRef boundary = Fixture(2048, 1);
    CGImageRef result = BRCreateLeftMirroredPixels(boundary);
    require(result != NULL && CGImageGetWidth(result) == 1 && CGImageGetHeight(result) == 2048,
            @"normalized dimension boundary accepted");
    CGImageRelease(result); CGImageRelease(boundary);

    const char *processorNames[] = {"Camera.CameraPhotoCaptureProcessor", "_TtC6Camera27CameraPhotoCaptureProcessor"};
    for (size_t i = 0; i < 2; i++) {
        require(BRFrontCaptureNeedsCompensation(true, processorNames[i]), @"verified front processor compensated");
        require(!BRFrontCaptureNeedsCompensation(false, processorNames[i]), @"back processor untouched");
    }
    const char *otherNames[] = {NULL, "", "CameraKitData.PhotoCaptureDelegate",
        "_TtC13CameraKitData20PhotoCaptureDelegate", "Camera.CameraPhotoCaptureProcessorExtra",
        "_TtC6Camera28CameraPhotoCaptureProcessor", "Other.CameraPhotoCaptureProcessor"};
    for (size_t i = 0; i < sizeof(otherNames) / sizeof(otherNames[0]); i++) {
        require(!BRFrontCaptureNeedsCompensation(true, otherNames[i]), @"unverified delegate untouched");
        require(!BRFrontCaptureNeedsCompensation(false, otherNames[i]), @"unverified back delegate untouched");
    }
}

int main(void) {
    @autoreleasepool {
        GuardTests();
        CompareFixture(4, 4, @"four-color corners");
        CompareFixture(13, 7, @"asymmetric landscape");
        CompareFixture(3, 11, @"asymmetric portrait");
        puts("Front orientation tests passed: ImageIO EXIF 5 oracle, exact pixels, self-inverse and scoped guards");
    }
    return 0;
}
