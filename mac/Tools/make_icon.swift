// Renders the LC Helper app icon into an .iconset directory.
// Usage: make_icon <output.iconset>
import AppKit

// LillianCare CI: petrol #004E64 body (lighter #00667F at the top), logo mark on top.
let navyTop = NSColor(srgbRed: 0x00 / 255, green: 0x66 / 255, blue: 0x7f / 255, alpha: 1)
let navy = NSColor(srgbRed: 0x00 / 255, green: 0x4e / 255, blue: 0x64 / 255, alpha: 1)
// The brand pin mark (public/brand/logo-mark.svg, 40×32 viewBox); path given as the 2nd argument.
var logoMark: NSImage?

func render(pixels: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: 1024, height: 1024) // draw in 1024-pt design space
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current?.imageInterpolation = .high

    // macOS icon grid: 824×824 body centred in 1024 canvas, ~185 corner radius.
    let body = NSRect(x: 100, y: 100, width: 824, height: 824)
    let shape = NSBezierPath(roundedRect: body, xRadius: 185, yRadius: 185)

    // Soft drop shadow.
    NSGraphicsContext.saveGraphicsState()
    let shadow = NSShadow()
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.35)
    shadow.shadowOffset = NSSize(width: 0, height: -12)
    shadow.shadowBlurRadius = 28
    shadow.set()
    navy.setFill()
    shape.fill()
    NSGraphicsContext.restoreGraphicsState()

    // Subtle vertical gradient.
    NSGradient(starting: navyTop, ending: navy)?.draw(in: shape, angle: -90)

    // Hairline inner highlight.
    NSColor.white.withAlphaComponent(0.08).setStroke()
    let rim = NSBezierPath(roundedRect: body.insetBy(dx: 3, dy: 3), xRadius: 182, yRadius: 182)
    rim.lineWidth = 6
    rim.stroke()

    // LillianCare pin mark, centred.
    if let mark = logoMark {
        let w: CGFloat = 560, h = w * 32 / 40
        mark.draw(in: NSRect(x: 512 - w / 2 + 12, y: 512 - h / 2 - 8, width: w, height: h))
    }

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    FileHandle.standardError.write(Data("usage: make_icon <output.iconset> [logo-mark.svg]\n".utf8))
    exit(64)
}
let out = URL(fileURLWithPath: args[1])
if args.count >= 3 { logoMark = NSImage(contentsOfFile: args[2]) }
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

for base in [16, 32, 128, 256, 512] {
    try render(pixels: base).write(to: out.appendingPathComponent("icon_\(base)x\(base).png"))
    try render(pixels: base * 2).write(to: out.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
