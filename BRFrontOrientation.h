#ifndef BR_FRONT_ORIENTATION_H
#define BR_FRONT_ORIENTATION_H

#include <CoreGraphics/CoreGraphics.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

// Only this verified 4.93.0 processor fixes the front image's orientation to
// UIImageOrientationLeftMirrored (EXIF 5). The CameraKitData delegate has no
// corresponding evidence and must receive the ordinary normalized pixels.
static inline bool BRFrontCaptureNeedsCompensation(bool front, const char *delegateName) {
    if (!front || !delegateName) return false;
    return strcmp(delegateName, "Camera.CameraPhotoCaptureProcessor") == 0 ||
           strcmp(delegateName, "_TtC6Camera27CameraPhotoCaptureProcessor") == 0;
}

// Materialize EXIF 5's transpose rather than attaching orientation metadata.
// Transposing twice restores the original image, so the native front processor
// cancels this compensation. The caller owns the returned image (Create rule).
// Input is the already normalized <=2048-pixel image, never the original asset.
static inline CGImageRef BRCreateLeftMirroredPixels(CGImageRef image) {
    if (!image) return NULL;
    const size_t width = CGImageGetWidth(image);
    const size_t height = CGImageGetHeight(image);
    if (!width || !height || width > 2048 || height > 2048) return NULL;

    CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if (!colorSpace) return NULL;
    // The non-square image's axes exchange places. The dimension bound also
    // bounds allocation and bytes-per-row arithmetic to 16 MiB / 8192 bytes.
    CGContextRef context = CGBitmapContextCreate(NULL, height, width, 8, height * 4,
        colorSpace, kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(colorSpace);
    if (!context) return NULL;

    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextSetInterpolationQuality(context, kCGInterpolationNone);
    CGContextSetShouldAntialias(context, false);
    // CG uses bottom-left coordinates. This maps (x, y) to (H-y, W-x),
    // which is the top-left pixel transpose specified by EXIF orientation 5.
    CGContextConcatCTM(context, CGAffineTransformMake(0, -1, -1, 0,
                                                    (CGFloat)height, (CGFloat)width));
    CGContextDrawImage(context, CGRectMake(0, 0, (CGFloat)width, (CGFloat)height), image);
    CGImageRef result = CGBitmapContextCreateImage(context);
    CGContextRelease(context);
    return result;
}

#endif
