<p align="center">
  <img src="assets/icon.png" width="128" height="128" alt="Dexo App Icon" />
</p>

<h1 align="center">Dexo</h1>

<p align="center">A native iOS client for Discourse forums, built with UIKit + Swift.</p>
<p align="center">A fork of <a href="https://github.com/Eilgnaw/dexo">Eilgnaw/dexo</a> focused on linux.do (and idcflare.com) on iOS 15.</p>

<p align="center">
  English | <a href="README.zh-CN.md">中文</a>
</p>

## Screenshots

| Home  | Topic Detail | Categories |
|:---:|:---:|:---:|
| ![Home](assets/home.png) | ![Topic Detail](assets/detail.png) | ![Categories](assets/cate.png) |


## Features

- [x] **Multi-Forum Management** — Add, switch, and remove multiple Discourse instances
- [x] **Topic Browsing** — Latest / Top topic lists with infinite scrolling
- [x] **Categories & Tags** — Browse topics by category or tag
- [x] **Topic Detail** — HTML content rendering, image viewer, code blocks, collapsible sections
- [x] **Reply & Create Topic** — Reply to topics or specific posts, publish new topics
- [x] **Notifications** — Real-time notification updates via MessageBus long-polling
- [x] **Private Messages** — View messages with unread indicators, mark as read on tap
- [x] **Secure Auth** — RSA-based Discourse User API Key authentication with Keychain storage
- [x] **Appearance** — System / Light / Dark mode with custom theme color support

## What's new vs upstream

This fork keeps the upstream Discourse client and adds linux.do / idcflare.com support on iOS 15:

- [x] **iOS 15.0 floor** — Shipping minimum is iOS 15.0. Unsigned Release IPAs go to GitHub Releases; PR CI also uploads a Debug IPA artifact
- [x] **Password login** — Username/password for linux.do and idcflare.com (hCaptcha, TOTP 2FA). Discourse `invalid_second_factor_method` is treated as a 2FA challenge, not a hard fail
- [x] **Guest Cloudflare pass** — Guest “过盾” uses the same `WKWebsiteDataStore` as login so `cf_clearance` matches
- [x] **Authenticated in-app browser** — WKWebView primes `_t` / `_forum_session` / `cf_clearance` from the app jar. Logged-in HTTPS post links and Settings / Me **打开网页** use it. Skips the iOS 15-broken `linux.do/login` SPA so `connect.linux.do` OAuth (e.g. cdk.linux.do, api.coee.ccwu.cc) can complete
- [x] **Cookie-Editor export** — Settings / Me copies Cookie-Editor JSON for Safari import
- [x] **Third-party IME** — Password field is visible by default; secure entry is on only while hiding, so iOS 15 third-party keyboards keep working
- [x] **Crash diagnostics** — Login breadcrumbs plus a copyable last-crash alert on cold start
- [x] **WebView DoH** — Upstream already has DoH `URLProtocol`; this fork also applies DoH to production WKWebViews via a CONNECT proxy on iOS 17+

## Tech Stack

| Component | Detail |
|-----------|--------|
| Language | Swift 5 |
| UI Framework | UIKit |
| Minimum Target | iOS 15.0 |
| Architecture | MVVM + `@Observable` |
| Build Tool | [Tuist](https://tuist.dev) |
| Database | SQLite ([GRDB](https://github.com/groue/GRDB.swift)) |
| Networking | [Alamofire](https://github.com/Alamofire/Alamofire) |
| Image Loading | [SDWebImage](https://github.com/SDWebImage/SDWebImage) |
| Image Viewer | [Lightbox](https://github.com/hyperoslo/Lightbox) |

## Getting Started

### Prerequisites

- Xcode 16+
- [mise](https://mise.jdx.dev) (runtime version manager)

### Build

```bash
# Install tools, fetch dependencies, and generate the Xcode project
make setup

# Re-generate the project only
make generate

# Clean
make clean
```

Open the generated `dexo.xcodeproj`, select your development team, then build and run.

## Project Structure

```
dexo/
├── Core/
│   ├── Auth/           # Auth flow, Keychain, RSA encryption
│   ├── Networking/     # DoH URLProtocol
│   ├── Observable/     # ObservableViewController base class
│   └── Settings/       # App preferences
├── Database/           # GRDB database manager & models
├── Features/
│   ├── ForumList/      # Forum list
│   ├── ForumDetail/
│   │   ├── Home/       # Latest / Top topics
│   │   ├── Categories/ # Category browsing
│   │   ├── Tags/       # Tag-based browsing
│   │   ├── Messages/   # Private messages
│   │   ├── Notifications/ # Notifications
│   │   └── TopicDetail/   # Topic detail & replies
│   └── Settings/       # Settings
├── Networking/
│   ├── DiscourseAPI.swift    # API client
│   ├── DiscourseRouter.swift # Route definitions
│   └── Models/               # API response models
└── Assets.xcassets/
```

## Releases

Unsigned IPAs are published on [GitHub Releases](https://github.com/jaffliang/dexo/releases) after the IPA workflow runs (`v2.0-build.NNN`). Pull requests also upload a Debug IPA artifact.

## Credit

Based on [Eilgnaw/dexo](https://github.com/Eilgnaw/dexo). This fork: [jaffliang/dexo](https://github.com/jaffliang/dexo).

## Related Projects

- **[Dexo Push Relay](https://github.com/Eilgnaw/dexo-push-relay)** — Stateless Web Push to APNs relay

## Links

- **[Linux.do](https://linux.do)**
