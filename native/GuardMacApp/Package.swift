// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "GuardMacApp",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "GuardMacApp", targets: ["GuardMacApp"])
    ],
    targets: [
        .executableTarget(
            name: "GuardMacApp",
            path: "Sources/GuardMacApp"
        ),
        .testTarget(
            name: "GuardMacAppTests",
            dependencies: ["GuardMacApp"],
            path: "Tests/GuardMacAppTests"
        )
    ]
)
