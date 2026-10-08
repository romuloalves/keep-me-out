// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "KeepMeOut",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "KeepMeOut",
            linkerSettings: [
                .linkedFramework("SwiftUI"),
                .linkedFramework("AppKit"),
            ]
        )
    ]
)
