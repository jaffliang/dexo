<p align="center">
  <img src="assets/icon.png" width="128" height="128" alt="Dexo App Icon" />
</p>

<h1 align="center">Dexo</h1>

<p align="center">一个原生 iOS Discourse 论坛客户端，使用 UIKit + Swift 构建。</p>
<p align="center">基于 <a href="https://github.com/Eilgnaw/dexo">Eilgnaw/dexo</a> 的 fork，面向 linux.do（以及 idcflare.com），支持 iOS 15。</p>

<p align="center">
  <a href="README.md">English</a> | 中文
</p>

## 截图

| 论坛首页  | 帖子详情 | 板块分类 |
|:---:|:---:|:---:|
| ![论坛首页](assets/home.png) | ![帖子详情](assets/detail.png) | ![板块分类](assets/cate.png) |


## 功能

- [x] **多论坛管理** — 添加、切换、删除多个 Discourse 实例
- [x] **帖子浏览** — 最新 / 热门话题列表，无限滚动加载
- [x] **分类 & 标签** — 按板块或标签浏览话题
- [x] **帖子详情** — HTML 内容渲染、图片查看、代码块展示、折叠内容
- [x] **回复 & 发帖** — 回复话题或针对特定楼层回复，发布新帖子
- [x] **通知** — 通过 MessageBus 长轮询实时接收通知更新
- [x] **私信** — 查看私信列表，未读标记，点击自动标记已读
- [x] **安全认证** — 基于 RSA 加密的 Discourse User API Key 认证流程，凭证存储在 Keychain
- [x] **外观设置** — 跟随系统 / 浅色 / 深色模式，支持自定义主题色

## 本 fork 增强

在上游 Discourse 客户端之上，补齐 linux.do / idcflare.com 在 iOS 15 上的能力：

- [x] **最低 iOS 15.0** — 发版底线为 iOS 15.0。GitHub Actions 产出未签名 Release IPA；PR CI 额外上传 Debug IPA artifact
- [x] **账密登录** — linux.do 与 idcflare.com 支持用户名/密码（hCaptcha、TOTP 2FA）。Discourse 的 `invalid_second_factor_method` 按二次验证挑战处理，而不是直接失败
- [x] **游客过盾** — 游客 Cloudflare 挑战与登录共用同一 `WKWebsiteDataStore`，`cf_clearance` 与登录一致
- [x] **带登录态的应用内浏览器** — WKWebView 会从应用 Cookie 罐写入 `_t` / `_forum_session` / `cf_clearance`。已登录时，帖子里的 HTTPS 链接以及设置 /「我」的**打开网页**走该浏览器。会跳过 iOS 15 上会卡死的 `linux.do/login` SPA，以便完成 `connect.linux.do` OAuth（如 cdk.linux.do、api.coee.ccwu.cc）
- [x] **Cookie-Editor 导出** — 设置 /「我」可复制 Cookie-Editor JSON，供 Safari 导入
- [x] **第三方输入法** — 密码框默认明文；仅在用户选择隐藏时启用安全输入，避免 iOS 15 屏蔽搜狗等第三方键盘
- [x] **崩溃诊断** — 登录面包屑，以及冷启动时可复制的上次崩溃信息
- [x] **WebView DoH（iOS 17+）** — 上游已有 DoH `URLProtocol`；本 fork 在 iOS 17+ 还会通过 CONNECT 代理把 DoH 应用到正式 WKWebView。iOS 15 上 WKWebView **不**走该代理
- [x] **URLSession / Alamofire DoH 网关（iOS 15）** — 论坛 API、话题列表、账密登录和 URLSession 图片可通过应用内环回网关使用自定义 HTTPS DoH URL。内置解析器 + 自定义。切换解析器在主线程外探测（约 4 秒上限），失败则回退或关闭，避免启动黑屏。仅覆盖 API 路径，不是全浏览器 DoH
- [x] **ECH / HTTP/2 / brotli** — ECH 编进网关（ECH 编不过则构建失败，不会静默降级）。源站发布 HTTPS RR 时使用。Cloudflare 选择 `h2` 时走 HTTP/2；该路径支持 brotli 解码
- [x] **阅读时间上报** — linux.do 与 idcflare 各有独立开关（linux.do 默认关，idcflare 默认开）。未登录不上报，也不显示未读计时标记。开启后楼层号旁会出现小蓝点，该楼阅读时间计入后消失。连续失败 3 次后仅关闭对应站点开关，以免触发风控；可在设置中重新开启，并在上报记录中查看状态

## 技术栈

| 项目 | 说明 |
|------|------|
| 语言 | Swift 5 |
| UI 框架 | UIKit |
| 最低版本 | iOS 15.0 |
| 架构 | MVVM + `@Observable` |
| 构建工具 | [Tuist](https://tuist.dev) |
| 数据库 | SQLite ([GRDB](https://github.com/groue/GRDB.swift)) |
| 网络 | [Alamofire](https://github.com/Alamofire/Alamofire) |
| 图片加载 | [SDWebImage](https://github.com/SDWebImage/SDWebImage) |
| 图片查看 | [Lightbox](https://github.com/hyperoslo/Lightbox) |

## 快速开始

### 前置要求

- Xcode 16+
- [mise](https://mise.jdx.dev) (工具版本管理)

### 构建

```bash
# 安装工具、拉取依赖、生成 Xcode 工程（一步到位）
make setup

# 后续只需重新生成工程
make generate

# 清理
make clean
```

执行完成后打开生成的 `dexo.xcodeproj`，选择开发团队后即可编译运行。

## 项目结构

```
dexo/
├── Core/
│   ├── Auth/           # 认证流程、Keychain、RSA 加解密
│   ├── Networking/     # DoH URLProtocol + iOS 15 环回网关
│   ├── Observable/     # ObservableViewController 基类
│   └── Settings/       # 应用偏好设置
├── Database/           # GRDB 数据库管理 & 数据模型
├── Features/
│   ├── ForumList/      # 论坛列表
│   ├── ForumDetail/
│   │   ├── Home/       # 最新 / 热门话题
│   │   ├── Categories/ # 板块分类
│   │   ├── Tags/       # 标签话题
│   │   ├── Messages/   # 私信
│   │   ├── Notifications/ # 通知
│   │   └── TopicDetail/   # 帖子详情 & 回复
│   └── Settings/       # 设置页
├── Networking/
│   ├── DiscourseAPI.swift    # API 客户端
│   ├── DiscourseRouter.swift # 路由定义
│   └── Models/               # API 响应模型
└── Assets.xcassets/
```

## 发布

IPA 工作流跑完后，未签名 IPA 会发布到 [GitHub Releases](https://github.com/jaffliang/dexo/releases)，标签形如 `v2.2-build.NNN`。Pull Request 的 CI 也会上传 Debug IPA artifact。

## 致谢

基于 [Eilgnaw/dexo](https://github.com/Eilgnaw/dexo)。本 fork：[jaffliang/dexo](https://github.com/jaffliang/dexo)。

## 关联项目

- **[Dexo Push Relay](https://github.com/Eilgnaw/dexo-push-relay)** — 无状态 Web Push 至 APNs 中继

## 友链

- **[Linux.do](https://linux.do)** — 学 AI，上 L 站
