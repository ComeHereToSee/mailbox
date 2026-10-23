import AppKit
import SwiftUI

extension NSColor {
    convenience init?(hex: String) {
        var s = hex.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("#") { s.removeFirst() }
        guard s.count == 6, let v = UInt32(s, radix: 16) else { return nil }
        self.init(srgbRed: CGFloat((v >> 16) & 0xFF) / 255, green: CGFloat((v >> 8) & 0xFF) / 255, blue: CGFloat(v & 0xFF) / 255, alpha: 1)
    }
}

extension Color {
    init(hex: String, fallback: Color = .accentColor) {
        if let c = NSColor(hex: hex) {
            self = Color(nsColor: c)
        } else {
            self = fallback
        }
    }

    /// Stable color for a name / address (avatars).
    static func forString(_ s: String) -> Color {
        let palette: [Color] = [.blue, .purple, .pink, .orange, .teal, .green, .indigo, .red, .mint, .cyan, .brown]
        var h: UInt32 = 5381
        for b in s.lowercased().utf8 { h = (h &* 33) &+ UInt32(b) }
        return palette[Int(h % UInt32(palette.count))]
    }
}
