// KeyboardEvent.code → RDP PC/XT scancode (set 1) map for the P2b TLV KEY wire
// message (ADR 0051). Extended keys carry the 0xE0 prefix in the HIGH byte of
// the u32 scancode (e.g. right-ctrl = 0xE01D), matching the Rust side's
// `(scancode >> 8) & 0xFF == 0xE0` extended-flag detection in stream.rs.
//
// `KeyboardEvent.code` is physical-layout-independent (KeyA is the A-position
// key regardless of QWERTY/AZERTY), which is exactly what RDP scancodes encode —
// so this map is layout-agnostic. The server applies its own keyboard layout to
// turn the scancode into a character.

// RDP_SCANCODES maps a KeyboardEvent.code to its RDP scancode (0xE0-prefixed for
// extended keys). Unmapped codes are dropped by the caller.
export const RDP_SCANCODES: Record<string, number> = {
  // --- row 1: function keys ---
  Escape: 0x01,
  F1: 0x3b,
  F2: 0x3c,
  F3: 0x3d,
  F4: 0x3e,
  F5: 0x3f,
  F6: 0x40,
  F7: 0x41,
  F8: 0x42,
  F9: 0x43,
  F10: 0x44,
  F11: 0x57,
  F12: 0x58,

  // --- number row ---
  Backquote: 0x29,
  Digit1: 0x02,
  Digit2: 0x03,
  Digit3: 0x04,
  Digit4: 0x05,
  Digit5: 0x06,
  Digit6: 0x07,
  Digit7: 0x08,
  Digit8: 0x09,
  Digit9: 0x0a,
  Digit0: 0x0b,
  Minus: 0x0c,
  Equal: 0x0d,
  Backspace: 0x0e,

  // --- top letter row ---
  Tab: 0x0f,
  KeyQ: 0x10,
  KeyW: 0x11,
  KeyE: 0x12,
  KeyR: 0x13,
  KeyT: 0x14,
  KeyY: 0x15,
  KeyU: 0x16,
  KeyI: 0x17,
  KeyO: 0x18,
  KeyP: 0x19,
  BracketLeft: 0x1a,
  BracketRight: 0x1b,
  Backslash: 0x2b,

  // --- home row ---
  CapsLock: 0x3a,
  KeyA: 0x1e,
  KeyS: 0x1f,
  KeyD: 0x20,
  KeyF: 0x21,
  KeyG: 0x22,
  KeyH: 0x23,
  KeyJ: 0x24,
  KeyK: 0x25,
  KeyL: 0x26,
  Semicolon: 0x27,
  Quote: 0x28,
  Enter: 0x1c,

  // --- bottom row ---
  ShiftLeft: 0x2a,
  KeyZ: 0x2c,
  KeyX: 0x2d,
  KeyC: 0x2e,
  KeyV: 0x2f,
  KeyB: 0x30,
  KeyN: 0x31,
  KeyM: 0x32,
  Comma: 0x33,
  Period: 0x34,
  Slash: 0x35,
  ShiftRight: 0x36,

  // --- modifiers + space ---
  ControlLeft: 0x1d,
  MetaLeft: 0xe05b, // left Windows key (extended)
  AltLeft: 0x38,
  Space: 0x39,
  AltRight: 0xe038, // AltGr (extended)
  MetaRight: 0xe05c, // right Windows key (extended)
  ContextMenu: 0xe05d, // application/menu key (extended)
  ControlRight: 0xe01d, // right ctrl (extended)

  // --- navigation cluster (all extended) ---
  Insert: 0xe052,
  Delete: 0xe053,
  Home: 0xe047,
  End: 0xe04f,
  PageUp: 0xe049,
  PageDown: 0xe051,
  ArrowUp: 0xe048,
  ArrowDown: 0xe050,
  ArrowLeft: 0xe04b,
  ArrowRight: 0xe04d,

  // --- numpad ---
  NumLock: 0x45,
  NumpadDivide: 0xe035, // extended (the only numpad extended key)
  NumpadMultiply: 0x37,
  NumpadSubtract: 0x4a,
  NumpadAdd: 0x4e,
  NumpadEnter: 0xe01c, // extended
  NumpadDecimal: 0x53,
  Numpad0: 0x52,
  Numpad1: 0x4f,
  Numpad2: 0x50,
  Numpad3: 0x51,
  Numpad4: 0x4b,
  Numpad5: 0x4c,
  Numpad6: 0x4d,
  Numpad7: 0x47,
  Numpad8: 0x48,
  Numpad9: 0x49,

  // --- misc ---
  PrintScreen: 0xe037, // extended
  ScrollLock: 0x46,
  Pause: 0x45, // (simplified; true Pause is a multi-byte sequence)
}

// scancodeFor returns the RDP scancode for a KeyboardEvent.code, or undefined if
// the key is not mapped (caller drops it rather than send a bogus scancode).
export function scancodeFor(code: string): number | undefined {
  return RDP_SCANCODES[code]
}
