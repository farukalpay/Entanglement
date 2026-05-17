// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "EntanglementRuntime",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "RuntimeKit", targets: ["RuntimeKit"]),
        .executable(name: "ent-run", targets: ["EntRun"]),
        .executable(name: "runtime-self-test", targets: ["RuntimeSelfTest"]),
    ],
    targets: [
        .target(name: "RuntimeKit", path: "runtime/Sources/RuntimeKit"),
        .executableTarget(name: "EntRun", dependencies: ["RuntimeKit"], path: "runtime/Sources/EntRun"),
        .executableTarget(name: "RuntimeSelfTest", dependencies: ["RuntimeKit"], path: "runtime/Tests/RuntimeKitSelfTest"),
        .testTarget(name: "RuntimeKitTests", dependencies: ["RuntimeKit"], path: "runtime/Tests/RuntimeKitTests"),
    ]
)
