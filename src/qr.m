// QR module matrix via CoreImage, so `2fa enroll` can print a scannable code
// instead of a URI someone has to turn into one themselves.
//
// Why this rather than a QR encoder in Zig: CIQRCodeGenerator is a system
// framework and produces the matrix in a dozen lines. A correct encoder is
// Reed-Solomon over GF(256), version and capacity tables, eight mask patterns
// and their penalty scoring — several hundred lines of exactly the kind of code
// that is subtly wrong in ways only a phone notices. The project already
// bridges to ObjC for LocalAuthentication and the session dictionary, so this
// adds no new mechanism.
//
// Returns the matrix one byte per module (1 = dark), which the Zig side renders
// with half-block characters. Rendering is not done here because terminal
// width, quiet zone and colour are presentation, and presentation belongs where
// the rest of the output is written.

#import <Foundation/Foundation.h>
#import <CoreImage/CoreImage.h>

/// Fill `out` with the QR matrix for `text`, one byte per module.
///
/// Returns the side length in modules, or 0 on failure or if `out_cap` is too
/// small — the caller cannot render a partial matrix, and a truncated QR that
/// still scans would be worse than none.
int secretctl_qr_matrix(const char *text, unsigned char *out, int out_cap) {
    @autoreleasepool {
        if (!text || !out || out_cap <= 0) return 0;

        NSData *payload = [[NSString stringWithUTF8String:text]
            dataUsingEncoding:NSISOLatin1StringEncoding];
        // otpauth URIs are ASCII, so Latin-1 is exact. UTF-8 is the fallback
        // rather than the default because CIQRCodeGenerator treats the input as
        // bytes, and byte mode is what every scanner reads back.
        if (!payload) {
            payload = [[NSString stringWithUTF8String:text] dataUsingEncoding:NSUTF8StringEncoding];
        }
        if (!payload) return 0;

        CIFilter *f = [CIFilter filterWithName:@"CIQRCodeGenerator"];
        if (!f) return 0;
        [f setValue:payload forKey:@"inputMessage"];
        // M (~15% recovery). L would be denser-tolerant of nothing and H makes
        // the code physically larger, which matters when it has to fit a
        // terminal window.
        [f setValue:@"M" forKey:@"inputCorrectionLevel"];

        CIImage *img = f.outputImage;
        if (!img) return 0;

        // The generator emits exactly one pixel per module, so extent is the
        // module count. It includes the mandatory 4-module quiet zone already.
        int side = (int)img.extent.size.width;
        if (side <= 0 || side * side > out_cap) return 0;

        CIContext *ctx = [CIContext contextWithOptions:nil];
        CGImageRef cg = [ctx createCGImage:img fromRect:img.extent];
        if (!cg) return 0;

        // Render to a known 8-bit grey buffer rather than trusting the CGImage's
        // native format: CoreImage is free to hand back whatever it likes, and
        // reading raw bytes from an unexamined format is how "works on my
        // machine" starts.
        CGColorSpaceRef grey = CGColorSpaceCreateDeviceGray();
        unsigned char *px = calloc((size_t)side * (size_t)side, 1);
        if (!px) { CGColorSpaceRelease(grey); CGImageRelease(cg); return 0; }
        CGContextRef bmp = CGBitmapContextCreate(px, (size_t)side, (size_t)side, 8,
                                                 (size_t)side, grey, kCGImageAlphaNone);
        if (!bmp) { free(px); CGColorSpaceRelease(grey); CGImageRelease(cg); return 0; }
        CGContextDrawImage(bmp, CGRectMake(0, 0, side, side), cg);

        for (int y = 0; y < side; y++) {
            for (int x = 0; x < side; x++) {
                // CoreImage's origin is bottom-left; terminals draw top-down.
                unsigned char v = px[(size_t)(side - 1 - y) * (size_t)side + (size_t)x];
                out[(size_t)y * (size_t)side + (size_t)x] = (v < 128) ? 1 : 0;
            }
        }

        CGContextRelease(bmp);
        free(px);
        CGColorSpaceRelease(grey);
        CGImageRelease(cg);
        return side;
    }
}
