import ProjectDescription

let developmentTeam = Environment.developmentTeam.getString(default: "")
let pushRelayHost = Environment.pushRelayHost.getString(default: "")

let project = Project(
    name: "dexo",
    options: .options(
        defaultKnownRegions: ["en", "zh-Hans"],
        developmentRegion: "en"
    ),
        packages: [
        .local(path: "Packages/CookedHTML"),
        .local(path: "Packages/PushCrypto"),
        .local(path: "Packages/DoHGatewayPolicy"),
    ],
    settings: .settings(
        base: [
            "DEVELOPMENT_TEAM": .string(developmentTeam),
        ],
        configurations: [
            .debug(name: "Debug", settings: [:], xcconfig: nil),
            .release(name: "Release", settings: [:], xcconfig: nil),
        ]
    ),
    targets: [
        .target(
            name: "dexo",
            destinations: .iOS,
            product: .app,
            bundleId: "com.eilgnaw.dexo",
            deploymentTargets: .iOS("15.0"),
            infoPlist: .file(path: "dexo/Info.plist"),
            sources: [
                .glob("dexo/**", excluding: [
                    "dexo/Info.plist",
                    "dexo/PrivacyInfo.xcprivacy",
                    "dexo/Assets.xcassets/**",
                    "dexo/AppIcon.icon/**",
                    "dexo/AppIconWhite.icon/**",
                    "dexo/AppIconBlack.icon/**",
                    "dexo/AppIconOcean.icon/**",
                    "dexo/AppIconEmber.icon/**",
                    "dexo/AppIconForest.icon/**",
                    "dexo/dexo-Bridging-Header.h",
                ]),
            ],
            resources: .resources([
                .glob(pattern: "dexo/Assets.xcassets/**"),
                .glob(pattern: "dexo/AppIcon.icon/**"),
                .glob(pattern: "dexo/AppIconWhite.icon/**"),
                .glob(pattern: "dexo/AppIconBlack.icon/**"),
                .glob(pattern: "dexo/AppIconOcean.icon/**"),
                .glob(pattern: "dexo/AppIconEmber.icon/**"),
                .glob(pattern: "dexo/AppIconForest.icon/**"),
                .glob(pattern: "dexo/Localizable.xcstrings"),
                .glob(pattern: "dexo/Core/aliases.json"),
                .glob(pattern: "dexo/PrivacyInfo.xcprivacy"),
            ]),
            entitlements: .file(path: "dexo/dexo.entitlements"),
            dependencies: [
                .external(name: "Alamofire"),
                .external(name: "GRDB"),
                .external(name: "SDWebImage"),
                .external(name: "SDWebImageSVGCoder"),
                .external(name: "Lightbox"),
                .package(product: "CookedHTML"),
                .package(product: "PushCrypto"),
                .package(product: "DoHGatewayPolicy"),
                .target(name: "DexoNotificationService"),
                .external(name: "DanmakuKit"),
                .external(name: "Perception"),
            ],
            settings: .settings(
                base: [
                    "ASSETCATALOG_COMPILER_ALTERNATE_APPICON_NAMES": "AppIconWhite AppIconBlack AppIconOcean AppIconEmber AppIconForest",
                    "ASSETCATALOG_COMPILER_APPICON_NAME": "AppIcon",
                    "ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME": "AccentColor",
                    "ASSETCATALOG_COMPILER_INCLUDE_ALL_APPICON_ASSETS": "YES",
                    "CODE_SIGN_STYLE": "Automatic",
                    "CURRENT_PROJECT_VERSION": "2",
                    "DEXO_PUSH_RELAY_HOST": .string(pushRelayHost),
                    "GENERATE_INFOPLIST_FILE": "YES",
                    "HEADER_SEARCH_PATHS": "$(inherited) $(SRCROOT)/dexo $(SRCROOT)/dexo/Core $(SRCROOT)/Native/DoHGateway/include",
                    "LIBRARY_SEARCH_PATHS": "$(inherited) $(SRCROOT)/Native/DoHGateway/dist/$(PLATFORM_NAME)",
                    "INFOPLIST_KEY_CFBundleDisplayName": "Dexo",
                    "INFOPLIST_KEY_LSApplicationCategoryType": "public.app-category.utilities",
                    "INFOPLIST_KEY_UIApplicationSupportsIndirectInputEvents": "YES",
                    "INFOPLIST_KEY_UISupportedInterfaceOrientations": "UIInterfaceOrientationPortrait UIInterfaceOrientationLandscapeLeft UIInterfaceOrientationLandscapeRight",
                    "INFOPLIST_KEY_UISupportedInterfaceOrientations_iPad": "UIInterfaceOrientationLandscapeLeft UIInterfaceOrientationLandscapeRight UIInterfaceOrientationPortrait UIInterfaceOrientationPortraitUpsideDown",
                    "LD_RUNPATH_SEARCH_PATHS": "$(inherited) @executable_path/Frameworks",
                    "OTHER_LDFLAGS": "$(inherited) -ObjC -lc++ -framework Security -framework SystemConfiguration -force_load $(SRCROOT)/Native/DoHGateway/dist/$(PLATFORM_NAME)/libdexo_doh_gateway.a",
                    "MARKETING_VERSION": "2.2",
                    "PRODUCT_NAME": "dexo",
                    "STRING_CATALOG_GENERATE_SYMBOLS": "YES",
                    "SWIFT_APPROACHABLE_CONCURRENCY": "YES",
                    "SWIFT_DEFAULT_ACTOR_ISOLATION": "MainActor",
                    "SWIFT_EMIT_LOC_STRINGS": "YES",
                    "SWIFT_OBJC_BRIDGING_HEADER": "dexo/dexo-Bridging-Header.h",
                    "SWIFT_UPCOMING_FEATURE_MEMBER_IMPORT_VISIBILITY": "YES",
                    "SWIFT_VERSION": "5.0",
                    "TARGETED_DEVICE_FAMILY": "1,2",
                ],
                configurations: [
                    .debug(name: "Debug", settings: ["DEXO_APNS_ENVIRONMENT": "development"]),
                    .release(name: "Release", settings: ["DEXO_APNS_ENVIRONMENT": "production"]),
                ]
            )
        ),
        .target(
            name: "DexoNotificationService",
            destinations: .iOS,
            product: .appExtension,
            bundleId: "com.eilgnaw.dexo.NotificationService",
            deploymentTargets: .iOS("15.0"),
            infoPlist: .extendingDefault(with: [
                "CFBundleDisplayName": "Dexo",
                "DexoPushAppGroup": "group.com.eilgnaw.dexo.push",
                "DexoPushKeychainAccessGroup": "$(AppIdentifierPrefix)com.eilgnaw.dexo.pushkeys",
                "DexoPushRelayHost": "$(DEXO_PUSH_RELAY_HOST)",
                "NSExtension": [
                    "NSExtensionPointIdentifier": "com.apple.usernotifications.service",
                    "NSExtensionPrincipalClass": "$(PRODUCT_MODULE_NAME).NotificationService",
                ],
            ]),
            sources: ["DexoNotificationService/**"],
            resources: ["DexoNotificationService/Localizable.xcstrings"],
            entitlements: .file(path: "DexoNotificationService/DexoNotificationService.entitlements"),
            dependencies: [
                .package(product: "PushCrypto"),
            ],
            settings: .settings(
                base: [
                    "APPLICATION_EXTENSION_API_ONLY": "YES",
                    "CODE_SIGN_STYLE": "Automatic",
                    "CURRENT_PROJECT_VERSION": "2",
                    "DEXO_PUSH_RELAY_HOST": .string(pushRelayHost),
                    "GENERATE_INFOPLIST_FILE": "YES",
                    "MARKETING_VERSION": "2.2",
                    "PRODUCT_NAME": "DexoNotificationService",
                    "SKIP_INSTALL": "YES",
                    "SWIFT_DEFAULT_ACTOR_ISOLATION": "nonisolated",
                    "SWIFT_VERSION": "5.0",
                    "TARGETED_DEVICE_FAMILY": "1,2",
                ]
            )
        ),
        .target(
            name: "dexoTests",
            destinations: .iOS,
            product: .unitTests,
            bundleId: "com.eilgnaw.dexoTests",
            deploymentTargets: .iOS("15.0"),
            infoPlist: .default,
            sources: ["dexoTests/**"],
            dependencies: [
                .target(name: "dexo"),
            ],
            settings: .settings(
                base: [
                    "GENERATE_INFOPLIST_FILE": "YES",
                    "PRODUCT_NAME": "dexoTests",
                    "SWIFT_DEFAULT_ACTOR_ISOLATION": "MainActor",
                    "SWIFT_VERSION": "5.0",
                ]
            )
        ),
    ]
)
