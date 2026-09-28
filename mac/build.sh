#!/usr/bin/env bash
# Builds "LC Helper.app" (release), ad-hoc signs it and copies it to ~/Applications.
set -euo pipefail

MAC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="LC Helper"
EXECUTABLE="LCHelper"
BUNDLE_ID="care.lillian.helper"
VERSION="${LC_HELPER_VERSION:-1.0.0}"
BUILD_NUMBER="$(date +%Y%m%d%H%M)"

BUILD_DIR="$MAC_DIR/build"
APP_DIR="$BUILD_DIR/$APP_NAME.app"
DEST_DIR="$HOME/Applications"
DEST_APP="$DEST_DIR/$APP_NAME.app"

cd "$MAC_DIR"

echo "==> Compiling (release)"
swift build -c release
BIN_DIR="$(swift build -c release --show-bin-path)"

echo "==> Rendering app icon"
mkdir -p "$BUILD_DIR"
ICON_TOOL="$BUILD_DIR/make_icon"
if [[ ! -x "$ICON_TOOL" || "$MAC_DIR/Tools/make_icon.swift" -nt "$ICON_TOOL" ]]; then
  swiftc -O -o "$ICON_TOOL" "$MAC_DIR/Tools/make_icon.swift"
fi
ICONSET="$BUILD_DIR/AppIcon.iconset"
rm -rf "$ICONSET"
"$ICON_TOOL" "$ICONSET" "$MAC_DIR/../public/brand/logo-mark.svg"
iconutil -c icns -o "$BUILD_DIR/AppIcon.icns" "$ICONSET"

echo "==> Assembling $APP_NAME.app"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
cp "$BIN_DIR/$EXECUTABLE" "$APP_DIR/Contents/MacOS/$EXECUTABLE"
cp "$BUILD_DIR/AppIcon.icns" "$APP_DIR/Contents/Resources/AppIcon.icns"
printf 'APPL????' > "$APP_DIR/Contents/PkgInfo"

cat > "$APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>$EXECUTABLE</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundleDisplayName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$BUILD_NUMBER</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.developer-tools</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
  <key>NSHumanReadableCopyright</key>
  <string>LillianCare internal developer tool</string>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsLocalNetworking</key>
    <true/>
    <key>NSExceptionDomains</key>
    <dict>
      <key>localhost</key>
      <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
        <key>NSIncludesSubdomains</key>
        <false/>
      </dict>
    </dict>
  </dict>
</dict>
</plist>
PLIST
plutil -lint "$APP_DIR/Contents/Info.plist"

echo "==> Signing (ad-hoc)"
codesign --force --deep -s - "$APP_DIR"
codesign -v --strict "$APP_DIR"

echo "==> Installing to $DEST_APP"
mkdir -p "$DEST_DIR"
rm -rf "$DEST_APP"
ditto "$APP_DIR" "$DEST_APP"
codesign -v --strict "$DEST_APP"
# Refresh LaunchServices so the new icon / bundle info are picked up.
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
[[ -x "$LSREGISTER" ]] && "$LSREGISTER" -f "$DEST_APP" >/dev/null 2>&1 || true

echo "==> Done: $DEST_APP (version $VERSION, build $BUILD_NUMBER)"
