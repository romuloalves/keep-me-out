import SwiftUI

@main
struct KeepMeOutApp: App {
    var body: some Scene {
        WindowGroup("Keep Me Out") {
            ContentView()
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 440, height: 580)
    }
}
