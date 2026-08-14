import UIKit

final class DoHSettingsViewController: ObservableViewController {
    override var backgroundStyle: BackgroundStyle { .grouped }

    private enum Section: Int, CaseIterable {
        case overview
        case control
        case servers
    }

    private let settings = AppSettings.shared
    private let themeManager = ThemeManager.shared

    private lazy var tableView: UITableView = {
        let tableView = ThemedTableView(frame: .zero, style: .insetGrouped)
        tableView.translatesAutoresizingMaskIntoConstraints = false
        tableView.dataSource = self
        tableView.delegate = self
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 76
        tableView.register(DoHOverviewCell.self, forCellReuseIdentifier: DoHOverviewCell.reuseIdentifier)
        tableView.register(DoHServerCell.self, forCellReuseIdentifier: DoHServerCell.reuseIdentifier)
        return tableView
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "settings.doh.title")
        navigationItem.largeTitleDisplayMode = .never
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "plus"),
            style: .plain,
            target: self,
            action: #selector(addServer)
        )

        view.addSubview(tableView)
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.topAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    override func updateUI() {
        _ = FontManager.shared.scale
        _ = themeManager.revision
        _ = settings.dohEnabled
        _ = settings.dohServers
        _ = settings.defaultDoHServerID
        tableView.reloadData()
    }

    override func applyThemeBackground() {
        super.applyThemeBackground()
        guard isViewLoaded else { return }
        tableView.tintColor = themeManager.accentColor
        tableView.reloadData()
    }

    private func applyResolverSettings() {
        guard let server = settings.defaultDoHServer else {
            settings.dohEnabled = false
            _ = EncryptedDNSManager.shared.setEnabled(false, serverURLString: "")
            return
        }
        let wantedEnabled = settings.dohEnabled
        let started = EncryptedDNSManager.shared.setEnabled(
            wantedEnabled,
            serverURLString: server.urlString
        )
        if wantedEnabled && !started {
            settings.dohEnabled = false
            showEnableFailedAlert()
            tableView.reloadData()
        }
    }

    private func setDefaultServer(_ server: AppSettings.DoHServer) {
        guard settings.defaultDoHServerID != server.id else { return }
        settings.defaultDoHServerID = server.id
        applyResolverSettings()
        tableView.reloadSections(
            IndexSet([Section.overview.rawValue, Section.servers.rawValue]),
            with: .automatic
        )
    }

    @objc private func addServer() {
        showEditor(for: nil)
    }

    private func showEditor(for server: AppSettings.DoHServer?) {
        let editor = DoHServerEditorViewController(server: server) { [weak self] savedServer in
            guard let self else { return }
            let wasEmpty = settings.dohServers.isEmpty
            let wasDefault = settings.defaultDoHServerID == savedServer.id
            settings.saveDoHServer(savedServer)
            if wasEmpty {
                settings.defaultDoHServerID = savedServer.id
            }
            if settings.dohEnabled, wasEmpty || wasDefault {
                applyResolverSettings()
            }
            tableView.reloadData()
        }
        navigationController?.pushViewController(editor, animated: true)
    }

    private func confirmDelete(_ server: AppSettings.DoHServer) {
        let alert = UIAlertController(
            title: String(localized: "settings.doh.delete.title"),
            message: String(
                format: String(localized: "settings.doh.delete.message"),
                server.name
            ),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "action.cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: String(localized: "action.delete"), style: .destructive) { [weak self] _ in
            guard let self else { return }
            let deletedDefault = settings.defaultDoHServerID == server.id
            settings.deleteDoHServer(id: server.id)
            if settings.dohServers.isEmpty {
                settings.dohEnabled = false
            }
            if deletedDefault || settings.dohServers.isEmpty {
                applyResolverSettings()
            }
            tableView.reloadData()
        })
        present(alert, animated: true)
    }

    private func showNoServerAlert() {
        let alert = UIAlertController(
            title: String(localized: "settings.doh.no_server.title"),
            message: String(localized: "settings.doh.no_server.message"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "action.cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: String(localized: "settings.doh.add"), style: .default) { [weak self] _ in
            self?.addServer()
        })
        present(alert, animated: true)
    }

    private func showEnableFailedAlert() {
        let reason = DoHGatewayRuntime.shared.lastError
            ?? String(localized: "settings.doh.enable_failed.unknown")
        let message = String(localized: "settings.doh.enable_failed.message \(reason)")
            + "\n"
            + DoHGatewayRuntime.echCompiledLabel
        let alert = UIAlertController(
            title: String(localized: "settings.doh.enable_failed.title"),
            message: message,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "action.ok"), style: .default))
        present(alert, animated: true)
    }

    @objc private func dohSwitchChanged(_ sender: UISwitch) {
        guard !sender.isOn || settings.defaultDoHServer != nil else {
            sender.setOn(false, animated: true)
            showNoServerAlert()
            return
        }

        guard EncryptedDNSManager.shared.setEnabled(
            sender.isOn,
            serverURLString: settings.defaultDoHServer?.urlString ?? ""
        ) else {
            sender.setOn(false, animated: true)
            settings.dohEnabled = false
            showEnableFailedAlert()
            return
        }
        settings.dohEnabled = sender.isOn
        tableView.reloadSections(
            IndexSet([Section.overview.rawValue, Section.control.rawValue]),
            with: .automatic
        )
    }
}

// MARK: - UITableViewDataSource

extension DoHSettingsViewController: UITableViewDataSource {
    func numberOfSections(in tableView: UITableView) -> Int {
        Section.allCases.count
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch Section(rawValue: section)! {
        case .overview, .control:
            return 1
        case .servers:
            return settings.dohServers.count + 1
        }
    }

    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        guard Section(rawValue: section) == .servers else { return nil }
        return String(localized: "settings.doh.servers.header")
    }

    func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        switch Section(rawValue: section)! {
        case .overview:
            return nil
        case .control:
            return String(localized: "settings.doh.footer")
        case .servers:
            return settings.dohServers.isEmpty
                ? String(localized: "settings.doh.empty.message")
                : String(localized: "settings.doh.servers.footer")
        }
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        switch Section(rawValue: indexPath.section)! {
        case .overview:
            let cell = tableView.dequeueReusableCell(
                withIdentifier: DoHOverviewCell.reuseIdentifier,
                for: indexPath
            ) as! DoHOverviewCell
            cell.configure(
                isEnabled: settings.dohEnabled,
                serverName: settings.defaultDoHServer?.name,
                theme: themeManager,
                fontManager: FontManager.shared
            )
            return cell

        case .control:
            let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
            cell.textLabel?.text = String(localized: "settings.doh.enable.title")
            cell.textLabel?.font = FontManager.shared.font(size: 17)
            cell.detailTextLabel?.text = String(localized: "settings.doh.enable.subtitle")
            cell.detailTextLabel?.font = FontManager.shared.font(size: 13)
            cell.detailTextLabel?.textColor = .secondaryLabel
            cell.detailTextLabel?.numberOfLines = 2
            cell.selectionStyle = .none
            let toggle = UISwitch()
            toggle.isOn = settings.dohEnabled
            toggle.onTintColor = themeManager.accentColor
            toggle.addTarget(self, action: #selector(dohSwitchChanged(_:)), for: .valueChanged)
            cell.accessoryView = toggle
            return cell

        case .servers:
            let servers = settings.dohServers
            guard indexPath.row < servers.count else {
                let cell = UITableViewCell(style: .default, reuseIdentifier: nil)
                cell.textLabel?.text = String(localized: "settings.doh.add")
                cell.textLabel?.font = FontManager.shared.font(size: 17, weight: .medium)
                cell.textLabel?.textColor = themeManager.accentColor
                cell.imageView?.image = UIImage(systemName: "plus.circle.fill")
                cell.imageView?.tintColor = themeManager.accentColor
                cell.accessoryType = .disclosureIndicator
                return cell
            }

            let server = servers[indexPath.row]
            let cell = tableView.dequeueReusableCell(
                withIdentifier: DoHServerCell.reuseIdentifier,
                for: indexPath
            ) as! DoHServerCell
            cell.configure(
                server: server,
                isDefault: settings.defaultDoHServerID == server.id,
                theme: themeManager,
                fontManager: FontManager.shared,
                onMakeDefault: { [weak self] in self?.setDefaultServer(server) },
                onEdit: { [weak self] in self?.showEditor(for: server) },
                onDelete: { [weak self] in self?.confirmDelete(server) }
            )
            return cell
        }
    }
}

// MARK: - UITableViewDelegate

extension DoHSettingsViewController: UITableViewDelegate {
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard Section(rawValue: indexPath.section) == .servers else { return }
        let servers = settings.dohServers
        if indexPath.row == servers.count {
            addServer()
        } else {
            setDefaultServer(servers[indexPath.row])
        }
    }

    func tableView(
        _ tableView: UITableView,
        trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath
    ) -> UISwipeActionsConfiguration? {
        guard Section(rawValue: indexPath.section) == .servers,
              indexPath.row < settings.dohServers.count
        else { return nil }

        let server = settings.dohServers[indexPath.row]
        let deleteAction = UIContextualAction(
            style: .destructive,
            title: String(localized: "action.delete")
        ) { [weak self] _, _, completion in
            self?.confirmDelete(server)
            completion(true)
        }
        deleteAction.image = UIImage(systemName: "trash")

        let editAction = UIContextualAction(
            style: .normal,
            title: String(localized: "action.edit")
        ) { [weak self] _, _, completion in
            self?.showEditor(for: server)
            completion(true)
        }
        editAction.image = UIImage(systemName: "pencil")
        editAction.backgroundColor = themeManager.accentColor

        let configuration = UISwipeActionsConfiguration(actions: [deleteAction, editAction])
        configuration.performsFirstActionWithFullSwipe = false
        return configuration
    }
}

// MARK: - Overview Cell

private final class DoHOverviewCell: UITableViewCell {
    static let reuseIdentifier = "DoHOverviewCell"

    private let iconBackgroundView = UIView()
    private let iconView = UIImageView()
    private let titleLabel = UILabel()
    private let messageLabel = UILabel()
    private let statusLabel = DoHBadgeLabel()

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        selectionStyle = .none

        [iconBackgroundView, iconView, titleLabel, messageLabel, statusLabel].forEach {
            $0.translatesAutoresizingMaskIntoConstraints = false
        }
        iconView.contentMode = .scaleAspectFit
        titleLabel.numberOfLines = 1
        messageLabel.numberOfLines = 0
        messageLabel.textColor = .secondaryLabel
        statusLabel.layer.cornerRadius = 11
        statusLabel.layer.masksToBounds = true

        contentView.addSubview(iconBackgroundView)
        iconBackgroundView.addSubview(iconView)
        contentView.addSubview(titleLabel)
        contentView.addSubview(messageLabel)
        contentView.addSubview(statusLabel)

        NSLayoutConstraint.activate([
            iconBackgroundView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            iconBackgroundView.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 20),
            iconBackgroundView.widthAnchor.constraint(equalToConstant: 52),
            iconBackgroundView.heightAnchor.constraint(equalToConstant: 52),

            iconView.centerXAnchor.constraint(equalTo: iconBackgroundView.centerXAnchor),
            iconView.centerYAnchor.constraint(equalTo: iconBackgroundView.centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 28),
            iconView.heightAnchor.constraint(equalToConstant: 28),

            titleLabel.leadingAnchor.constraint(equalTo: iconBackgroundView.trailingAnchor, constant: 14),
            titleLabel.topAnchor.constraint(equalTo: iconBackgroundView.topAnchor, constant: 2),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: contentView.trailingAnchor, constant: -20),

            statusLabel.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            statusLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 7),
            statusLabel.trailingAnchor.constraint(lessThanOrEqualTo: contentView.trailingAnchor, constant: -20),
            statusLabel.heightAnchor.constraint(equalToConstant: 22),

            messageLabel.topAnchor.constraint(equalTo: iconBackgroundView.bottomAnchor, constant: 16),
            messageLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            messageLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20),
            messageLabel.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -20),
        ])
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func configure(
        isEnabled: Bool,
        serverName: String?,
        theme: ThemeManager,
        fontManager: FontManager
    ) {
        iconBackgroundView.backgroundColor = theme.codeBackgroundColor
        iconBackgroundView.layer.cornerRadius = 16
        iconView.image = UIImage(systemName: isEnabled ? "shield.lefthalf.filled" : "shield")
        iconView.tintColor = isEnabled ? theme.accentColor : .secondaryLabel

        titleLabel.font = fontManager.font(size: 20, weight: .semibold)
        titleLabel.text = String(localized: "settings.doh.overview.title")
        messageLabel.font = fontManager.font(size: 14)
        messageLabel.text = [
            String(localized: "settings.doh.overview.message"),
            DoHGatewayRuntime.echCompiledLabel,
        ].joined(separator: "\n")

        statusLabel.font = fontManager.font(size: 12, weight: .semibold)
        statusLabel.text = isEnabled
            ? String(
                format: String(localized: "settings.doh.status.enabled_format"),
                serverName ?? String(localized: "settings.doh.server")
            )
            : String(localized: "settings.doh.status.disabled")
        statusLabel.textColor = isEnabled ? theme.accentColor : .secondaryLabel
        statusLabel.backgroundColor = isEnabled
            ? theme.codeBackgroundColor
            : UIColor.secondaryLabel.withAlphaComponent(0.1)
    }
}

// MARK: - Server Cell

private final class DoHServerCell: UITableViewCell {
    static let reuseIdentifier = "DoHServerCell"

    private let iconBackgroundView = UIView()
    private let iconView = UIImageView()
    private let nameLabel = UILabel()
    private let endpointLabel = UILabel()
    private let defaultLabel = DoHBadgeLabel()
    private let menuButton = UIButton(type: .system)
    private let nameStack = UIStackView()

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)

        [iconBackgroundView, iconView, endpointLabel, menuButton, nameStack].forEach {
            $0.translatesAutoresizingMaskIntoConstraints = false
        }
        iconView.contentMode = .scaleAspectFit
        nameLabel.lineBreakMode = .byTruncatingTail
        endpointLabel.textColor = .secondaryLabel
        endpointLabel.lineBreakMode = .byTruncatingMiddle
        defaultLabel.layer.cornerRadius = 9
        defaultLabel.layer.masksToBounds = true
        menuButton.setImage(UIImage(systemName: "ellipsis.circle"), for: .normal)
        menuButton.showsMenuAsPrimaryAction = true
        nameStack.axis = .horizontal
        nameStack.alignment = .center
        nameStack.spacing = 7
        nameStack.addArrangedSubview(nameLabel)
        nameStack.addArrangedSubview(defaultLabel)
        defaultLabel.setContentCompressionResistancePriority(.required, for: .horizontal)

        contentView.addSubview(iconBackgroundView)
        iconBackgroundView.addSubview(iconView)
        contentView.addSubview(nameStack)
        contentView.addSubview(endpointLabel)
        contentView.addSubview(menuButton)

        NSLayoutConstraint.activate([
            iconBackgroundView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            iconBackgroundView.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            iconBackgroundView.widthAnchor.constraint(equalToConstant: 40),
            iconBackgroundView.heightAnchor.constraint(equalToConstant: 40),

            iconView.centerXAnchor.constraint(equalTo: iconBackgroundView.centerXAnchor),
            iconView.centerYAnchor.constraint(equalTo: iconBackgroundView.centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 21),
            iconView.heightAnchor.constraint(equalToConstant: 21),

            nameStack.leadingAnchor.constraint(equalTo: iconBackgroundView.trailingAnchor, constant: 12),
            nameStack.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 13),
            nameStack.trailingAnchor.constraint(lessThanOrEqualTo: menuButton.leadingAnchor, constant: -8),
            defaultLabel.heightAnchor.constraint(equalToConstant: 18),

            endpointLabel.leadingAnchor.constraint(equalTo: nameStack.leadingAnchor),
            endpointLabel.topAnchor.constraint(equalTo: nameStack.bottomAnchor, constant: 4),
            endpointLabel.trailingAnchor.constraint(equalTo: menuButton.leadingAnchor, constant: -8),
            endpointLabel.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -13),

            menuButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -12),
            menuButton.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            menuButton.widthAnchor.constraint(equalToConstant: 36),
            menuButton.heightAnchor.constraint(equalToConstant: 36),
        ])
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func prepareForReuse() {
        super.prepareForReuse()
        menuButton.menu = nil
    }

    func configure(
        server: AppSettings.DoHServer,
        isDefault: Bool,
        theme: ThemeManager,
        fontManager: FontManager,
        onMakeDefault: @escaping () -> Void,
        onEdit: @escaping () -> Void,
        onDelete: @escaping () -> Void
    ) {
        iconBackgroundView.backgroundColor = theme.codeBackgroundColor
        iconBackgroundView.layer.cornerRadius = 12
        iconView.image = UIImage(systemName: isDefault ? "checkmark.shield.fill" : "network")
        iconView.tintColor = isDefault ? theme.accentColor : .secondaryLabel

        nameLabel.text = server.name
        nameLabel.font = fontManager.font(size: 16, weight: isDefault ? .semibold : .regular)
        endpointLabel.text = server.urlString
        endpointLabel.font = fontManager.font(size: 12)

        defaultLabel.isHidden = !isDefault
        defaultLabel.text = String(localized: "settings.doh.default")
        defaultLabel.font = fontManager.font(size: 10, weight: .semibold)
        defaultLabel.textColor = theme.accentColor
        defaultLabel.backgroundColor = theme.codeBackgroundColor
        menuButton.tintColor = .secondaryLabel

        let defaultAction = UIAction(
            title: String(localized: "settings.doh.make_default"),
            image: UIImage(systemName: "checkmark.circle"),
            attributes: isDefault ? [.disabled] : []
        ) { _ in onMakeDefault() }

        let editAction = UIAction(
            title: String(localized: "action.edit"),
            image: UIImage(systemName: "pencil")
        ) { _ in onEdit() }
        let deleteAction = UIAction(
            title: String(localized: "action.delete"),
            image: UIImage(systemName: "trash"),
            attributes: .destructive
        ) { _ in onDelete() }

        menuButton.menu = UIMenu(children: [defaultAction, editAction, deleteAction])
        accessibilityHint = String(localized: "settings.doh.server.accessibility_hint")
    }
}

private final class DoHBadgeLabel: UILabel {
    override func drawText(in rect: CGRect) {
        super.drawText(in: rect.inset(by: UIEdgeInsets(top: 0, left: 8, bottom: 0, right: 8)))
    }

    override var intrinsicContentSize: CGSize {
        let size = super.intrinsicContentSize
        return CGSize(width: size.width + 16, height: size.height)
    }
}

// MARK: - Editor

private final class DoHServerEditorViewController: BaseViewController {
    override var backgroundStyle: BackgroundStyle { .grouped }

    private enum Field: Int, CaseIterable {
        case name
        case endpoint
    }

    private let originalServer: AppSettings.DoHServer?
    private let onSave: (AppSettings.DoHServer) -> Void
    private var name: String
    private var endpoint: String

    private lazy var tableView: UITableView = {
        let tableView = ThemedTableView(frame: .zero, style: .insetGrouped)
        tableView.translatesAutoresizingMaskIntoConstraints = false
        tableView.dataSource = self
        tableView.delegate = self
        tableView.keyboardDismissMode = .interactive
        tableView.register(DoHEditorFieldCell.self, forCellReuseIdentifier: DoHEditorFieldCell.reuseIdentifier)
        return tableView
    }()

    private lazy var saveButton = UIBarButtonItem(
        title: String(localized: "action.save"),
        style: .done,
        target: self,
        action: #selector(save)
    )

    init(server: AppSettings.DoHServer?, onSave: @escaping (AppSettings.DoHServer) -> Void) {
        originalServer = server
        self.onSave = onSave
        name = server?.name ?? "Cloudflare"
        endpoint = server?.urlString ?? "https://cloudflare-dns.com/dns-query"
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = originalServer == nil
            ? String(localized: "settings.doh.add")
            : String(localized: "settings.doh.edit")
        navigationItem.rightBarButtonItem = saveButton

        view.addSubview(tableView)
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.topAnchor),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        updateValidation()
    }

    override func applyThemeBackground() {
        super.applyThemeBackground()
        guard isViewLoaded else { return }
        tableView.tintColor = ThemeManager.shared.accentColor
        tableView.reloadData()
    }

    @objc private func textFieldChanged(_ sender: UITextField) {
        guard let field = Field(rawValue: sender.tag) else { return }
        switch field {
        case .name:
            name = sender.text ?? ""
        case .endpoint:
            endpoint = sender.text ?? ""
        }
        updateValidation()
    }

    private func updateValidation() {
        saveButton.isEnabled = EncryptedDNSManager.normalizedServerURL(endpoint) != nil
        guard let endpointCell = tableView.cellForRow(
            at: IndexPath(row: Field.endpoint.rawValue, section: 0)
        ) as? DoHEditorFieldCell else { return }
        let shouldShowError = !endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && EncryptedDNSManager.normalizedServerURL(endpoint) == nil
        endpointCell.setErrorVisible(shouldShowError)
    }

    @objc private func save() {
        guard let url = EncryptedDNSManager.normalizedServerURL(endpoint),
              let host = url.host
        else { return }
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let server = AppSettings.DoHServer(
            id: originalServer?.id ?? UUID(),
            name: trimmedName.isEmpty ? host : trimmedName,
            urlString: url.absoluteString
        )
        onSave(server)
        navigationController?.popViewController(animated: true)
    }
}

extension DoHServerEditorViewController: UITableViewDataSource, UITableViewDelegate {
    func numberOfSections(in tableView: UITableView) -> Int { 1 }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        Field.allCases.count
    }

    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        String(localized: "settings.doh.editor.header")
    }

    func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        String(localized: "settings.doh.editor.footer")
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let field = Field(rawValue: indexPath.row)!
        let cell = tableView.dequeueReusableCell(
            withIdentifier: DoHEditorFieldCell.reuseIdentifier,
            for: indexPath
        ) as! DoHEditorFieldCell
        cell.configure(
            title: field == .name
                ? String(localized: "settings.doh.name")
                : String(localized: "settings.doh.endpoint"),
            text: field == .name ? name : endpoint,
            placeholder: field == .name
                ? String(localized: "settings.doh.name.placeholder")
                : String(localized: "settings.doh.server.placeholder"),
            isURL: field == .endpoint,
            tag: field.rawValue,
            target: self,
            action: #selector(textFieldChanged(_:))
        )
        if field == .endpoint {
            let showError = !endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && EncryptedDNSManager.normalizedServerURL(endpoint) == nil
            cell.setErrorVisible(showError)
        }
        return cell
    }
}

private final class DoHEditorFieldCell: UITableViewCell {
    static let reuseIdentifier = "DoHEditorFieldCell"

    private let captionLabel = UILabel()
    private let textField = UITextField()
    private let errorLabel = UILabel()
    private let fieldStack = UIStackView()

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        selectionStyle = .none

        fieldStack.translatesAutoresizingMaskIntoConstraints = false
        fieldStack.axis = .vertical
        fieldStack.spacing = 4
        fieldStack.addArrangedSubview(captionLabel)
        fieldStack.addArrangedSubview(textField)
        fieldStack.addArrangedSubview(errorLabel)
        contentView.addSubview(fieldStack)
        captionLabel.textColor = .secondaryLabel
        textField.clearButtonMode = .whileEditing
        errorLabel.text = String(localized: "settings.doh.invalid.inline")
        errorLabel.textColor = .systemRed
        errorLabel.numberOfLines = 0
        errorLabel.isHidden = true

        NSLayoutConstraint.activate([
            fieldStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            fieldStack.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 11),
            fieldStack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            fieldStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -10),
            textField.heightAnchor.constraint(greaterThanOrEqualToConstant: 28),
        ])
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func configure(
        title: String,
        text: String,
        placeholder: String,
        isURL: Bool,
        tag: Int,
        target: Any,
        action: Selector
    ) {
        captionLabel.text = title
        captionLabel.font = FontManager.shared.font(size: 12, weight: .medium)
        textField.font = FontManager.shared.font(size: 16)
        errorLabel.font = FontManager.shared.font(size: 11)
        if textField.text != text { textField.text = text }
        textField.placeholder = placeholder
        textField.tag = tag
        textField.keyboardType = isURL ? .URL : .default
        textField.textContentType = isURL ? .URL : nil
        textField.autocapitalizationType = isURL ? .none : .words
        textField.autocorrectionType = isURL ? .no : .default
        textField.removeTarget(nil, action: nil, for: .editingChanged)
        textField.addTarget(target, action: action, for: .editingChanged)
    }

    func setErrorVisible(_ visible: Bool) {
        guard errorLabel.isHidden == visible else { return }
        errorLabel.isHidden = !visible
    }
}
