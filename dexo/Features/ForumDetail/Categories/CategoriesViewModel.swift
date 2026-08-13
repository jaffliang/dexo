import Foundation

import Perception

@Perceptible
final class CategoriesViewModel {
    var categories: [DiscourseCategory] = []
    var isLoading = false
    var errorMessage: String?
    var requiresLogin = false
    var requiresChallenge = false

    private let api: DiscourseAPI

    init(api: DiscourseAPI) {
        self.api = api
    }

    func loadCategories(forceRefresh: Bool = false) async {
        isLoading = true
        errorMessage = nil
        requiresLogin = false
        requiresChallenge = false
        do {
            let result = try await api.fetchAllCategories(forceRefresh: forceRefresh)
            categories = result.categoryList.categories.filter { $0.parentCategoryId == nil }
        } catch {
            let failure = GuestContentLoadFailure(error)
            requiresLogin = failure.requiresLogin
            requiresChallenge = failure.requiresChallenge
            errorMessage = failure.message
        }
        isLoading = false
    }
}
