// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "DoHGatewayPolicy",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "DoHGatewayPolicy", targets: ["DoHGatewayPolicy"]),
    ],
    targets: [
        .target(name: "DoHGatewayPolicy"),
        .testTarget(
            name: "DoHGatewayPolicyTests",
            dependencies: ["DoHGatewayPolicy"]
        ),
    ]
)
