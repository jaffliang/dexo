import UIKit

/// iOS 15 drops `UIPasteboard.general.string` set inside a dismissing alert.
/// Always pair `string` with `setItems` using the public UTF-8 type.
enum AppPasteboard {
    static func writePlainText(_ text: String) {
        let board = UIPasteboard.general
        board.string = text
        board.setItems([["public.utf8-plain-text": text]], options: [:])
    }
}
