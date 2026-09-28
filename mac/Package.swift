// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "LCHelper",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "LCHelper",
            path: "Sources/LCHelper",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("WebKit"),
                .linkedFramework("ServiceManagement"),
                .linkedFramework("UserNotifications"),
            ]
        )
    ]
)
