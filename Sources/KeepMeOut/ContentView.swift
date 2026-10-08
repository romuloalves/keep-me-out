import SwiftUI

@MainActor
final class Model: ObservableObject {
    @Published var domains: [String] = []
    @Published var blocking = false
    @Published var stale = false
    @Published var draft = ""
    @Published var actionError: String?
    @Published var statusError: String?
    @Published var busy = false

    private var engine: Engine?

    var banner: String? {
        if let actionError, !actionError.isEmpty {
            return actionError
        }
        if stale {
            return "Blocking stopped unexpectedly. Stop to restore DNS."
        }
        return statusError
    }

    init() {
        do {
            engine = try Engine.make()
        } catch {
            statusError = error.localizedDescription
        }
    }

    func watch() async {
        refresh()
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            refresh()
        }
    }

    func refresh() {
        guard let engine else { return }
        do {
            let status = try engine.status()
            domains = status.domains
            blocking = status.blocking
            stale = status.stale
            statusError = nil
        } catch {
            statusError = error.localizedDescription
        }
    }

    func add() {
        let input = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !input.isEmpty, let engine, !busy else { return }
        busy = true
        defer { busy = false }
        do {
            try engine.add(input)
            draft = ""
            actionError = nil
            refresh()
        } catch {
            actionError = error.localizedDescription
        }
    }

    func remove(_ domain: String) {
        guard let engine, !busy else { return }
        busy = true
        defer { busy = false }
        do {
            try engine.remove(domain)
            actionError = nil
            refresh()
        } catch {
            actionError = error.localizedDescription
        }
    }

    func toggle() {
        guard let engine, !busy else { return }
        let stopping = blocking || stale
        busy = true
        actionError = nil
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            defer {
                self.busy = false
                self.refresh()
            }
            do {
                if stopping {
                    try engine.stopBlocking()
                } else {
                    try engine.startBlocking()
                }
                self.actionError = nil
            } catch {
                self.actionError = error.localizedDescription
            }
        }
    }
}

struct ContentView: View {
    @StateObject private var model = Model()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 8) {
                Image(systemName: "circle.fill")
                    .font(.caption)
                    .foregroundStyle(model.blocking ? Color.red : (model.stale ? Color.orange : Color.green))
                    .accessibilityHidden(true)
                Text(model.blocking ? "Blocking" : "Not blocking")
                    .font(.title2.bold())
                Spacer()
                if model.busy {
                    ProgressView()
                        .controlSize(.small)
                }
            }

            if let banner = model.banner {
                Text(banner)
                    .font(.callout)
                    .foregroundStyle(model.stale && model.actionError == nil ? Color.orange : Color.red)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("banner")
            }

            Button(model.blocking || model.stale ? "Stop blocking" : "Start blocking") {
                model.toggle()
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.busy || (!model.blocking && !model.stale && model.domains.isEmpty))
            .accessibilityIdentifier("toggle-blocking")

            HStack(spacing: 8) {
                TextField("example.com or a link", text: $model.draft)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { model.add() }
                    .accessibilityIdentifier("domain-field")
                Button("Add") { model.add() }
                    .disabled(model.busy || model.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .accessibilityIdentifier("add-domain")
            }
            .onChange(of: model.draft) { _, _ in
                model.actionError = nil
            }

            Group {
                if model.domains.isEmpty {
                    Text("No domains yet")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List {
                        ForEach(model.domains, id: \.self) { domain in
                            HStack {
                                Text(domain)
                                Spacer()
                                Button("Remove") { model.remove(domain) }
                                    .buttonStyle(.borderless)
                            }
                        }
                    }
                    .listStyle(.inset)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))

            Text("A domain blocks that name and every subdomain. Browsers using Secure DNS, and iCloud Private Relay, bypass system DNS. Turn Secure DNS off in the browser for the block to apply there.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(20)
        .frame(minWidth: 440, minHeight: 560)
        .task { await model.watch() }
    }
}
