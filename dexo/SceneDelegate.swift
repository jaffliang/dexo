import UIKit

class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = (scene as? UIWindowScene) else { return }

        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = MainTabBarController()
        window.overrideUserInterfaceStyle = AppSettings.shared.appearanceMode.userInterfaceStyle
        ThemeManager.shared.apply(to: window)
        window.makeKeyAndVisible()
        self.window = window
        PushDeepLinkCoordinator.shared.activate(window: window)

        #if DEBUG
        FPSOverlay.shared.install(on: windowScene)
        #endif

        scheduleLastCrashPresentation()
    }

    func sceneDidDisconnect(_ scene: UIScene) {}
    func sceneDidBecomeActive(_ scene: UIScene) {
        scheduleLastCrashPresentation()
    }

    /// Copyable last-crash alert on cold start — does not require opening password login.
    /// The file is not deleted until Copy or OK.
    private func scheduleLastCrashPresentation() {
        guard let root = window?.rootViewController else { return }
        DispatchQueue.main.async {
            LastFatalExceptionPresenter.presentIfNeeded(from: root)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            LastFatalExceptionPresenter.presentIfNeeded(from: self?.window?.rootViewController)
        }
    }

    func sceneWillResignActive(_ scene: UIScene) {}
    func sceneWillEnterForeground(_ scene: UIScene) {
//        ProxyManager.shared.start()
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
//        ProxyManager.shared.stop()
    }
}
