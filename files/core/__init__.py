"""ZyberGuard core security-check modules.

Each module here is pure logic (plus, where it does network or
heavy I/O work, a small PyQt QObject worker meant to be moved onto a
QThread). None of these modules import anything from the GUI layer —
that keeps them independently testable and reusable from a CLI if
ever needed.
"""
