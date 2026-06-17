use ratatui::style::Color;
use std::io::Write;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Theme {
    pub name: &'static str,
    pub bg: Color,
    pub fg: Color,
    pub accent: Color,
    pub muted: Color,
    pub border: Color,
    pub highlight_bg: Color,
    pub highlight_fg: Color,
    pub stripe_bg: Color,
    pub key_bg: Color,
    pub key_fg: Color,
    pub tag: Color,
    pub panel_bg: Color,
    // Hex dump colors
    pub hex_null: Color,
    pub hex_ascii: Color,
    pub hex_space: Color,
    pub hex_high: Color,
    pub hex_other: Color,
    pub hex_offset: Color,
    /// 8 flow colors for visual grouping of packet flows.
    /// Each theme has its own palette derived from its accent/character colors.
    pub flow_colors: [Color; 8],
}

// ── Per-theme flow palettes (dark) ────────────────────────────────────

/// Default dark: cool pastels (cyan accent)
const FLOW_DEFAULT_DARK: [Color; 8] = [
    Color::Rgb(130, 220, 255), // sky (accent family)
    Color::Rgb(255, 150, 150), // rose
    Color::Rgb(180, 255, 180), // mint
    Color::Rgb(255, 210, 130), // peach
    Color::Rgb(200, 170, 255), // lavender
    Color::Rgb(130, 230, 220), // teal
    Color::Rgb(255, 180, 220), // pink
    Color::Rgb(220, 220, 140), // lime
];

/// Gruvbox dark: earthy warm tones
const FLOW_GRUVBOX_DARK: [Color; 8] = [
    Color::Rgb(250, 189, 47),  // yellow (gruvbox yellow)
    Color::Rgb(204, 36, 29),   // red (gruvbox red, lightened)
    Color::Rgb(184, 187, 38),  // green (gruvbox green)
    Color::Rgb(254, 128, 25),  // orange (gruvbox orange)
    Color::Rgb(211, 134, 155), // purple (gruvbox purple, lightened)
    Color::Rgb(131, 165, 152), // aqua (gruvbox aqua)
    Color::Rgb(235, 219, 178), // fg (gruvbox fg)
    Color::Rgb(169, 182, 101), // olive-green
];

/// Solarized dark: solarized accent palette
const FLOW_SOLARIZED_DARK: [Color; 8] = [
    Color::Rgb(42, 161, 152),  // cyan (solarized cyan)
    Color::Rgb(220, 50, 47),   // red
    Color::Rgb(133, 153, 0),   // green
    Color::Rgb(181, 137, 0),   // yellow
    Color::Rgb(108, 113, 196), // violet
    Color::Rgb(38, 139, 210),  // blue
    Color::Rgb(211, 54, 130),  // magenta
    Color::Rgb(203, 75, 22),   // orange
];

/// Ayu dark: warm amber/orange palette
const FLOW_AYU_DARK: [Color; 8] = [
    Color::Rgb(255, 180, 84),  // orange (ayu accent)
    Color::Rgb(255, 110, 80),  // coral
    Color::Rgb(170, 217, 76),  // green (ayu green)
    Color::Rgb(95, 196, 220),  // blue (ayu blue)
    Color::Rgb(210, 154, 230), // purple (ayu purple)
    Color::Rgb(255, 238, 153), // gold
    Color::Rgb(240, 130, 160), // pink
    Color::Rgb(150, 220, 190), // seafoam
];

/// Flexoki dark: natural ink tones
const FLOW_FLEXOKI_DARK: [Color; 8] = [
    Color::Rgb(208, 162, 21),  // yellow (flexoki yellow)
    Color::Rgb(210, 82, 82),   // red (flexoki red)
    Color::Rgb(102, 156, 72),  // green (flexoki green)
    Color::Rgb(36, 131, 123),  // cyan (flexoki cyan)
    Color::Rgb(142, 139, 206), // purple (flexoki purple)
    Color::Rgb(218, 112, 44),  // orange (flexoki orange)
    Color::Rgb(206, 93, 151),  // magenta (flexoki magenta)
    Color::Rgb(91, 163, 207),  // blue (flexoki blue)
];

/// Zoegi dark: muted desaturated greens
const FLOW_ZOEGI_DARK: [Color; 8] = [
    Color::Rgb(128, 200, 160), // mint (zoegi accent)
    Color::Rgb(200, 140, 140), // dusty rose
    Color::Rgb(150, 180, 210), // steel blue (zoegi tag)
    Color::Rgb(210, 190, 130), // sand
    Color::Rgb(170, 160, 200), // muted lavender
    Color::Rgb(130, 200, 200), // pale teal
    Color::Rgb(200, 170, 150), // warm grey
    Color::Rgb(180, 200, 140), // sage
];

/// FFE Dark: nord-inspired cool blues
const FLOW_FFE_DARK: [Color; 8] = [
    Color::Rgb(79, 214, 190),  // teal (ffe accent)
    Color::Rgb(240, 169, 136), // salmon (ffe highlight)
    Color::Rgb(163, 190, 140), // green (nord green)
    Color::Rgb(137, 220, 235), // ice blue (ffe tag)
    Color::Rgb(180, 142, 173), // mauve (nord purple)
    Color::Rgb(235, 203, 139), // sand (nord yellow)
    Color::Rgb(191, 151, 210), // light purple
    Color::Rgb(143, 188, 187), // frost (nord frost)
];

/// Postrboard dark: vibrant modern palette
const FLOW_POSTRBOARD_DARK: [Color; 8] = [
    Color::Rgb(79, 182, 232),  // blue (postrboard accent)
    Color::Rgb(251, 138, 77),  // orange (postrboard highlight)
    Color::Rgb(74, 222, 128),  // green (postrboard green)
    Color::Rgb(96, 165, 250),  // lighter blue (postrboard tag)
    Color::Rgb(232, 121, 197), // pink
    Color::Rgb(250, 204, 21),  // yellow
    Color::Rgb(167, 139, 250), // purple
    Color::Rgb(45, 212, 191),  // teal
];

// ── Per-theme flow palettes (light) ──────────────────────────────────

/// Default light: crisp cool tones (cyan accent family)
const FLOW_DEFAULT_LIGHT: [Color; 8] = [
    Color::Rgb(0, 120, 170),  // ocean blue (accent family)
    Color::Rgb(190, 30, 45),  // cherry red
    Color::Rgb(10, 135, 55),  // emerald
    Color::Rgb(195, 105, 0),  // tangerine
    Color::Rgb(115, 55, 190), // iris
    Color::Rgb(0, 138, 125),  // jade
    Color::Rgb(175, 40, 120), // fuchsia
    Color::Rgb(95, 115, 15),  // chartreuse
];

/// Gruvbox light: gruvbox dark accents on cream
const FLOW_GRUVBOX_LIGHT: [Color; 8] = [
    Color::Rgb(175, 58, 3),   // orange (gruvbox orange)
    Color::Rgb(157, 0, 6),    // red (gruvbox red)
    Color::Rgb(121, 116, 14), // green (gruvbox green)
    Color::Rgb(181, 118, 20), // yellow-brown (gruvbox yellow)
    Color::Rgb(143, 63, 113), // purple (gruvbox purple)
    Color::Rgb(69, 133, 136), // aqua (gruvbox aqua)
    Color::Rgb(7, 102, 120),  // blue-teal (gruvbox blue)
    Color::Rgb(130, 100, 10), // olive
];

/// Solarized light: solarized accent palette (same hues, works on cream)
const FLOW_SOLARIZED_LIGHT: [Color; 8] = [
    Color::Rgb(42, 161, 152),  // cyan
    Color::Rgb(220, 50, 47),   // red
    Color::Rgb(133, 153, 0),   // green
    Color::Rgb(181, 137, 0),   // yellow
    Color::Rgb(108, 113, 196), // violet
    Color::Rgb(38, 139, 210),  // blue
    Color::Rgb(211, 54, 130),  // magenta
    Color::Rgb(203, 75, 22),   // orange
];

/// Flexoki light: flexoki ink colors on paper
const FLOW_FLEXOKI_LIGHT: [Color; 8] = [
    Color::Rgb(173, 131, 1),  // yellow (flexoki yellow)
    Color::Rgb(175, 48, 51),  // red (flexoki red)
    Color::Rgb(76, 128, 46),  // green (flexoki green)
    Color::Rgb(36, 131, 123), // cyan (flexoki cyan)
    Color::Rgb(100, 92, 187), // purple (flexoki purple)
    Color::Rgb(188, 93, 11),  // orange (flexoki orange)
    Color::Rgb(165, 55, 120), // magenta (flexoki magenta)
    Color::Rgb(32, 90, 165),  // blue (flexoki blue)
];

/// Ayu light: warm accents on white
const FLOW_AYU_LIGHT: [Color; 8] = [
    Color::Rgb(230, 138, 0),   // orange (ayu accent)
    Color::Rgb(200, 55, 40),   // red
    Color::Rgb(110, 150, 0),   // green (ayu green)
    Color::Rgb(55, 160, 190),  // blue (ayu blue)
    Color::Rgb(163, 122, 204), // purple (ayu purple)
    Color::Rgb(170, 100, 10),  // amber
    Color::Rgb(180, 50, 100),  // magenta
    Color::Rgb(0, 130, 110),   // teal
];

/// Zoegi light: muted earth tones on white
const FLOW_ZOEGI_LIGHT: [Color; 8] = [
    Color::Rgb(40, 100, 75),  // deep green (zoegi accent family)
    Color::Rgb(150, 50, 50),  // muted red
    Color::Rgb(60, 95, 140),  // steel blue (zoegi tag family)
    Color::Rgb(150, 120, 30), // dark gold
    Color::Rgb(100, 80, 140), // muted purple
    Color::Rgb(0, 110, 110),  // dark teal
    Color::Rgb(140, 80, 60),  // sienna
    Color::Rgb(80, 110, 40),  // olive
];

/// FFE light: nord-inspired deeper tones
const FLOW_FFE_LIGHT: [Color; 8] = [
    Color::Rgb(20, 120, 100), // deep teal (ffe accent family)
    Color::Rgb(180, 80, 50),  // deep salmon (ffe highlight family)
    Color::Rgb(80, 140, 70),  // forest green
    Color::Rgb(30, 110, 140), // deep blue (ffe tag family)
    Color::Rgb(130, 80, 130), // plum
    Color::Rgb(150, 120, 30), // dark gold
    Color::Rgb(120, 70, 150), // purple
    Color::Rgb(0, 120, 120),  // dark cyan
];

/// Postrboard light: vivid modern on white
const FLOW_POSTRBOARD_LIGHT: [Color; 8] = [
    Color::Rgb(2, 110, 170),  // blue (postrboard accent family)
    Color::Rgb(194, 65, 12),  // burnt orange (postrboard highlight)
    Color::Rgb(22, 128, 61),  // green
    Color::Rgb(12, 74, 110),  // navy (postrboard tag)
    Color::Rgb(168, 50, 130), // magenta
    Color::Rgb(161, 130, 0),  // gold
    Color::Rgb(109, 60, 170), // purple
    Color::Rgb(0, 140, 130),  // teal
];

pub const THEMES: &[Theme] = &[
    // ── Dark themes ─────────────────────────────────────────────────
    // 0: Default
    Theme {
        name: "Default",
        bg: Color::Rgb(22, 22, 30),
        fg: Color::White,
        accent: Color::Rgb(0, 217, 255),
        muted: Color::DarkGray,
        border: Color::DarkGray,
        highlight_bg: Color::Rgb(40, 40, 60),
        highlight_fg: Color::Rgb(255, 220, 100),
        stripe_bg: Color::Rgb(28, 28, 34),
        key_bg: Color::DarkGray,
        key_fg: Color::Black,
        tag: Color::Rgb(180, 140, 255),
        panel_bg: Color::Rgb(24, 24, 30),
        hex_null: Color::DarkGray,
        hex_ascii: Color::Rgb(0, 200, 80),
        hex_space: Color::Rgb(0, 180, 200),
        hex_high: Color::Rgb(180, 140, 255),
        hex_other: Color::Rgb(255, 200, 60),
        hex_offset: Color::DarkGray,
        flow_colors: FLOW_DEFAULT_DARK,
    },
    // 1: Gruvbox
    Theme {
        name: "Gruvbox",
        bg: Color::Rgb(29, 32, 33),
        fg: Color::Rgb(235, 219, 178),
        accent: Color::Rgb(215, 153, 33),
        muted: Color::Rgb(146, 131, 116),
        border: Color::Rgb(62, 57, 54),
        highlight_bg: Color::Rgb(50, 48, 47),
        highlight_fg: Color::Rgb(250, 189, 47),
        stripe_bg: Color::Rgb(40, 40, 40),
        key_bg: Color::Rgb(80, 73, 69),
        key_fg: Color::Rgb(235, 219, 178),
        tag: Color::Rgb(131, 165, 152),
        panel_bg: Color::Rgb(37, 36, 36),
        hex_null: Color::Rgb(146, 131, 116),
        hex_ascii: Color::Rgb(184, 187, 38),
        hex_space: Color::Rgb(131, 165, 152),
        hex_high: Color::Rgb(211, 134, 155),
        hex_other: Color::Rgb(250, 189, 47),
        hex_offset: Color::Rgb(146, 131, 116),
        flow_colors: FLOW_GRUVBOX_DARK,
    },
    // 2: Solarized
    Theme {
        name: "Solarized",
        bg: Color::Rgb(0, 43, 54),
        fg: Color::Rgb(253, 246, 227),
        accent: Color::Rgb(42, 161, 152),
        muted: Color::Rgb(131, 148, 150),
        border: Color::Rgb(16, 58, 68),
        highlight_bg: Color::Rgb(7, 54, 66),
        highlight_fg: Color::Rgb(253, 246, 227),
        stripe_bg: Color::Rgb(3, 48, 58),
        key_bg: Color::Rgb(88, 110, 117),
        key_fg: Color::Rgb(253, 246, 227),
        tag: Color::Rgb(108, 113, 196),
        panel_bg: Color::Rgb(7, 54, 66),
        hex_null: Color::Rgb(131, 148, 150),
        hex_ascii: Color::Rgb(133, 153, 0),
        hex_space: Color::Rgb(42, 161, 152),
        hex_high: Color::Rgb(108, 113, 196),
        hex_other: Color::Rgb(181, 137, 0),
        hex_offset: Color::Rgb(131, 148, 150),
        flow_colors: FLOW_SOLARIZED_DARK,
    },
    // 3: Ayu
    Theme {
        name: "Ayu",
        bg: Color::Rgb(10, 14, 20),
        fg: Color::Rgb(191, 191, 191),
        accent: Color::Rgb(255, 153, 64),
        muted: Color::Rgb(92, 103, 115),
        border: Color::Rgb(40, 44, 52),
        highlight_bg: Color::Rgb(20, 24, 32),
        highlight_fg: Color::Rgb(255, 180, 84),
        stripe_bg: Color::Rgb(15, 19, 26),
        key_bg: Color::Rgb(60, 66, 76),
        key_fg: Color::Rgb(191, 191, 191),
        tag: Color::Rgb(210, 154, 230),
        panel_bg: Color::Rgb(18, 22, 30),
        hex_null: Color::Rgb(92, 103, 115),
        hex_ascii: Color::Rgb(170, 217, 76),
        hex_space: Color::Rgb(95, 196, 220),
        hex_high: Color::Rgb(210, 154, 230),
        hex_other: Color::Rgb(255, 180, 84),
        hex_offset: Color::Rgb(92, 103, 115),
        flow_colors: FLOW_AYU_DARK,
    },
    // 4: Flexoki
    Theme {
        name: "Flexoki",
        bg: Color::Rgb(16, 15, 15),
        fg: Color::Rgb(206, 205, 195),
        accent: Color::Rgb(36, 131, 123),
        muted: Color::Rgb(135, 133, 128),
        border: Color::Rgb(40, 39, 38),
        highlight_bg: Color::Rgb(28, 27, 26),
        highlight_fg: Color::Rgb(208, 162, 21),
        stripe_bg: Color::Rgb(22, 21, 20),
        key_bg: Color::Rgb(52, 51, 49),
        key_fg: Color::Rgb(206, 205, 195),
        tag: Color::Rgb(142, 139, 206),
        panel_bg: Color::Rgb(24, 23, 22),
        hex_null: Color::Rgb(135, 133, 128),
        hex_ascii: Color::Rgb(102, 156, 72),
        hex_space: Color::Rgb(36, 131, 123),
        hex_high: Color::Rgb(142, 139, 206),
        hex_other: Color::Rgb(208, 162, 21),
        hex_offset: Color::Rgb(135, 133, 128),
        flow_colors: FLOW_FLEXOKI_DARK,
    },
    // 5: Zoegi
    Theme {
        name: "Zoegi",
        bg: Color::Rgb(20, 20, 20),
        fg: Color::Rgb(204, 204, 204),
        accent: Color::Rgb(64, 128, 104),
        muted: Color::Rgb(89, 89, 89),
        border: Color::Rgb(48, 48, 48),
        highlight_bg: Color::Rgb(34, 34, 34),
        highlight_fg: Color::Rgb(128, 200, 160),
        stripe_bg: Color::Rgb(27, 27, 27),
        key_bg: Color::Rgb(64, 64, 64),
        key_fg: Color::Rgb(204, 204, 204),
        tag: Color::Rgb(150, 180, 210),
        panel_bg: Color::Rgb(28, 28, 28),
        hex_null: Color::Rgb(89, 89, 89),
        hex_ascii: Color::Rgb(80, 180, 120),
        hex_space: Color::Rgb(80, 160, 180),
        hex_high: Color::Rgb(150, 180, 210),
        hex_other: Color::Rgb(128, 200, 160),
        hex_offset: Color::Rgb(89, 89, 89),
        flow_colors: FLOW_ZOEGI_DARK,
    },
    // 6: FFE Dark
    Theme {
        name: "FFE Dark",
        bg: Color::Rgb(30, 35, 43),
        fg: Color::Rgb(216, 222, 233),
        accent: Color::Rgb(79, 214, 190),
        muted: Color::Rgb(155, 162, 175),
        border: Color::Rgb(59, 66, 82),
        highlight_bg: Color::Rgb(46, 52, 64),
        highlight_fg: Color::Rgb(240, 169, 136),
        stripe_bg: Color::Rgb(26, 31, 39),
        key_bg: Color::Rgb(59, 66, 82),
        key_fg: Color::Rgb(216, 222, 233),
        tag: Color::Rgb(137, 220, 235),
        panel_bg: Color::Rgb(26, 31, 39),
        hex_null: Color::Rgb(155, 162, 175),
        hex_ascii: Color::Rgb(163, 190, 140),
        hex_space: Color::Rgb(79, 214, 190),
        hex_high: Color::Rgb(137, 220, 235),
        hex_other: Color::Rgb(240, 169, 136),
        hex_offset: Color::Rgb(155, 162, 175),
        flow_colors: FLOW_FFE_DARK,
    },
    // 7: Postrboard
    Theme {
        name: "Postrboard",
        bg: Color::Rgb(26, 27, 38),
        fg: Color::Rgb(226, 232, 240),
        accent: Color::Rgb(79, 182, 232),
        muted: Color::Rgb(124, 141, 163),
        border: Color::Rgb(42, 45, 61),
        highlight_bg: Color::Rgb(54, 58, 79),
        highlight_fg: Color::Rgb(251, 138, 77),
        stripe_bg: Color::Rgb(30, 31, 43),
        key_bg: Color::Rgb(54, 58, 79),
        key_fg: Color::Rgb(226, 232, 240),
        tag: Color::Rgb(96, 165, 250),
        panel_bg: Color::Rgb(22, 23, 31),
        hex_null: Color::Rgb(124, 141, 163),
        hex_ascii: Color::Rgb(74, 222, 128),
        hex_space: Color::Rgb(79, 182, 232),
        hex_high: Color::Rgb(96, 165, 250),
        hex_other: Color::Rgb(251, 138, 77),
        hex_offset: Color::Rgb(124, 141, 163),
        flow_colors: FLOW_POSTRBOARD_DARK,
    },
    // ── Light themes ────────────────────────────────────────────────
    // 8: Default Light
    Theme {
        name: "Default Light",
        bg: Color::Reset,
        fg: Color::Rgb(30, 33, 43),
        accent: Color::Rgb(0, 145, 200),
        muted: Color::Rgb(140, 145, 155),
        border: Color::Rgb(200, 205, 215),
        highlight_bg: Color::Rgb(215, 228, 242),
        highlight_fg: Color::Rgb(12, 60, 90),
        stripe_bg: Color::Rgb(243, 245, 250),
        key_bg: Color::Rgb(0, 145, 200),
        key_fg: Color::Rgb(255, 255, 255),
        tag: Color::Rgb(120, 70, 200),
        panel_bg: Color::Rgb(232, 236, 244),
        hex_null: Color::Rgb(170, 175, 185),
        hex_ascii: Color::Rgb(12, 132, 54),
        hex_space: Color::Rgb(0, 130, 175),
        hex_high: Color::Rgb(120, 70, 200),
        hex_other: Color::Rgb(200, 120, 0),
        hex_offset: Color::Rgb(155, 160, 172),
        flow_colors: FLOW_DEFAULT_LIGHT,
    },
    // 9: Gruvbox Light
    Theme {
        name: "Gruvbox Light",
        bg: Color::Rgb(251, 241, 199),
        fg: Color::Rgb(60, 56, 54),
        accent: Color::Rgb(215, 153, 33),
        muted: Color::Rgb(146, 131, 116),
        border: Color::Rgb(213, 196, 161),
        highlight_bg: Color::Rgb(235, 219, 178),
        highlight_fg: Color::Rgb(60, 56, 54),
        stripe_bg: Color::Rgb(249, 236, 186),
        key_bg: Color::Rgb(213, 196, 161),
        key_fg: Color::Rgb(60, 56, 54),
        tag: Color::Rgb(69, 133, 136),
        panel_bg: Color::Rgb(242, 233, 185),
        hex_null: Color::Rgb(146, 131, 116),
        hex_ascii: Color::Rgb(121, 116, 14),
        hex_space: Color::Rgb(69, 133, 136),
        hex_high: Color::Rgb(143, 63, 113),
        hex_other: Color::Rgb(175, 58, 3),
        hex_offset: Color::Rgb(146, 131, 116),
        flow_colors: FLOW_GRUVBOX_LIGHT,
    },
    // 10: Solarized Light
    Theme {
        name: "Solarized Light",
        bg: Color::Rgb(253, 246, 227),
        fg: Color::Rgb(88, 110, 117),
        accent: Color::Rgb(42, 161, 152),
        muted: Color::Rgb(147, 161, 161),
        border: Color::Rgb(220, 212, 188),
        highlight_bg: Color::Rgb(238, 232, 213),
        highlight_fg: Color::Rgb(7, 54, 66),
        stripe_bg: Color::Rgb(245, 239, 218),
        key_bg: Color::Rgb(220, 212, 188),
        key_fg: Color::Rgb(88, 110, 117),
        tag: Color::Rgb(108, 113, 196),
        panel_bg: Color::Rgb(238, 232, 213),
        hex_null: Color::Rgb(147, 161, 161),
        hex_ascii: Color::Rgb(133, 153, 0),
        hex_space: Color::Rgb(42, 161, 152),
        hex_high: Color::Rgb(108, 113, 196),
        hex_other: Color::Rgb(181, 137, 0),
        hex_offset: Color::Rgb(147, 161, 161),
        flow_colors: FLOW_SOLARIZED_LIGHT,
    },
    // 11: Flexoki Light
    Theme {
        name: "Flexoki Light",
        bg: Color::Rgb(255, 252, 240),
        fg: Color::Rgb(16, 15, 15),
        accent: Color::Rgb(36, 131, 123),
        muted: Color::Rgb(111, 110, 105),
        border: Color::Rgb(230, 228, 217),
        highlight_bg: Color::Rgb(242, 240, 229),
        highlight_fg: Color::Rgb(16, 15, 15),
        stripe_bg: Color::Rgb(247, 245, 234),
        key_bg: Color::Rgb(230, 228, 217),
        key_fg: Color::Rgb(16, 15, 15),
        tag: Color::Rgb(100, 92, 187),
        panel_bg: Color::Rgb(244, 241, 230),
        hex_null: Color::Rgb(111, 110, 105),
        hex_ascii: Color::Rgb(76, 128, 46),
        hex_space: Color::Rgb(36, 131, 123),
        hex_high: Color::Rgb(100, 92, 187),
        hex_other: Color::Rgb(173, 131, 1),
        hex_offset: Color::Rgb(111, 110, 105),
        flow_colors: FLOW_FLEXOKI_LIGHT,
    },
    // 12: Ayu Light
    Theme {
        name: "Ayu Light",
        bg: Color::Rgb(252, 252, 252),
        fg: Color::Rgb(92, 97, 102),
        accent: Color::Rgb(255, 153, 64),
        muted: Color::Rgb(153, 160, 166),
        border: Color::Rgb(207, 209, 210),
        highlight_bg: Color::Rgb(230, 230, 230),
        highlight_fg: Color::Rgb(92, 97, 102),
        stripe_bg: Color::Rgb(243, 244, 245),
        key_bg: Color::Rgb(207, 209, 210),
        key_fg: Color::Rgb(92, 97, 102),
        tag: Color::Rgb(163, 122, 204),
        panel_bg: Color::Rgb(242, 242, 242),
        hex_null: Color::Rgb(153, 160, 166),
        hex_ascii: Color::Rgb(134, 179, 0),
        hex_space: Color::Rgb(55, 160, 190),
        hex_high: Color::Rgb(163, 122, 204),
        hex_other: Color::Rgb(230, 138, 0),
        hex_offset: Color::Rgb(153, 160, 166),
        flow_colors: FLOW_AYU_LIGHT,
    },
    // 13: Zoegi Light
    Theme {
        name: "Zoegi Light",
        bg: Color::Rgb(255, 255, 255),
        fg: Color::Rgb(51, 51, 51),
        accent: Color::Rgb(55, 121, 97),
        muted: Color::Rgb(89, 89, 89),
        border: Color::Rgb(230, 230, 230),
        highlight_bg: Color::Rgb(235, 235, 235),
        highlight_fg: Color::Rgb(51, 51, 51),
        stripe_bg: Color::Rgb(247, 247, 247),
        key_bg: Color::Rgb(230, 230, 230),
        key_fg: Color::Rgb(51, 51, 51),
        tag: Color::Rgb(80, 120, 160),
        panel_bg: Color::Rgb(245, 245, 245),
        hex_null: Color::Rgb(89, 89, 89),
        hex_ascii: Color::Rgb(40, 120, 70),
        hex_space: Color::Rgb(40, 110, 130),
        hex_high: Color::Rgb(80, 120, 160),
        hex_other: Color::Rgb(150, 110, 30),
        hex_offset: Color::Rgb(89, 89, 89),
        flow_colors: FLOW_ZOEGI_LIGHT,
    },
    // 14: FFE Light
    Theme {
        name: "FFE Light",
        bg: Color::Rgb(232, 236, 240),
        fg: Color::Rgb(30, 35, 43),
        accent: Color::Rgb(42, 157, 132),
        muted: Color::Rgb(74, 80, 96),
        border: Color::Rgb(201, 205, 214),
        highlight_bg: Color::Rgb(221, 225, 232),
        highlight_fg: Color::Rgb(192, 121, 32),
        stripe_bg: Color::Rgb(245, 247, 250),
        key_bg: Color::Rgb(201, 205, 214),
        key_fg: Color::Rgb(30, 35, 43),
        tag: Color::Rgb(58, 142, 164),
        panel_bg: Color::Rgb(245, 247, 250),
        hex_null: Color::Rgb(74, 80, 96),
        hex_ascii: Color::Rgb(80, 140, 70),
        hex_space: Color::Rgb(42, 157, 132),
        hex_high: Color::Rgb(58, 142, 164),
        hex_other: Color::Rgb(192, 121, 32),
        hex_offset: Color::Rgb(74, 80, 96),
        flow_colors: FLOW_FFE_LIGHT,
    },
    // 15: Postrboard Light
    Theme {
        name: "Postrboard Light",
        bg: Color::Rgb(250, 250, 250),
        fg: Color::Rgb(17, 24, 39),
        accent: Color::Rgb(2, 132, 199),
        muted: Color::Rgb(100, 116, 139),
        border: Color::Rgb(203, 213, 225),
        highlight_bg: Color::Rgb(226, 232, 240),
        highlight_fg: Color::Rgb(194, 65, 12),
        stripe_bg: Color::Rgb(248, 250, 252),
        key_bg: Color::Rgb(203, 213, 225),
        key_fg: Color::Rgb(17, 24, 39),
        tag: Color::Rgb(12, 74, 110),
        panel_bg: Color::Rgb(241, 245, 249),
        hex_null: Color::Rgb(100, 116, 139),
        hex_ascii: Color::Rgb(22, 128, 61),
        hex_space: Color::Rgb(2, 132, 199),
        hex_high: Color::Rgb(12, 74, 110),
        hex_other: Color::Rgb(194, 65, 12),
        hex_offset: Color::Rgb(100, 116, 139),
        flow_colors: FLOW_POSTRBOARD_LIGHT,
    },
];

#[allow(dead_code)]
pub fn theme_index_by_name(name: &str) -> usize {
    THEMES.iter().position(|t| t.name == name).unwrap_or(0)
}

/// Detect theme from Ghostty terminal config.
///
/// Reads `~/.config/ghostty/config` (or macOS app support path) and
/// parses `theme = <name>` to map known Ghostty themes to hexcap themes.
pub fn detect_ghostty_theme() -> Option<usize> {
    if !crate::ui::helpers::is_ghostty() {
        return None;
    }

    let home = std::env::var("HOME").ok()?;
    let candidates = [
        format!("{home}/.config/ghostty/config"),
        format!("{home}/Library/Application Support/com.mitchellh.ghostty/config"),
    ];

    let content = candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())?;

    let theme_value = content.lines().find_map(|line| {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix("theme")?;
        let rest = rest.trim_start();
        let rest = rest.strip_prefix('=')?;
        let rest = rest.trim();
        if rest.is_empty() {
            return None;
        }
        Some(rest.to_string())
    })?;

    // Handle `dark:X,light:Y` syntax — pick based on system appearance.
    let theme_name = if theme_value.contains(':') {
        let prefer_light = is_system_light();
        let prefix = if prefer_light { "light:" } else { "dark:" };
        theme_value
            .split(',')
            .find_map(|part| {
                let part = part.trim();
                part.strip_prefix(prefix).map(|v| v.trim().to_string())
            })
            .unwrap_or(theme_value)
    } else {
        theme_value
    };

    let lower = theme_name.to_ascii_lowercase();

    // Order matters: check "light" variant first for each family
    if lower.contains("gruvbox") && lower.contains("light") {
        return Some(9);
    }
    if lower.contains("gruvbox") {
        return Some(1);
    }
    if lower.contains("solarized") && lower.contains("light") {
        return Some(10);
    }
    if lower.contains("solarized") {
        return Some(2);
    }
    if lower.contains("ayu") && lower.contains("light") {
        return Some(12);
    }
    if lower.contains("ayu") {
        return Some(3);
    }
    if lower.contains("flexoki") && lower.contains("light") {
        return Some(11);
    }
    if lower.contains("flexoki") {
        return Some(4);
    }
    if lower.contains("ffe") && lower.contains("light") {
        return Some(14);
    }
    if lower.contains("ffe") {
        return Some(6);
    }

    // Generic light fallback
    if lower.contains("light") {
        return Some(8);
    }

    None
}

/// Detect whether the system prefers a light colour scheme.
///
/// On macOS, checks `defaults read -g AppleInterfaceStyle`; if the command
/// fails or returns anything other than "Dark", the system is in light mode.
pub fn is_system_light() -> bool {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("defaults")
            .args(["read", "-g", "AppleInterfaceStyle"])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                let val = String::from_utf8_lossy(&o.stdout);
                !val.trim().eq_ignore_ascii_case("Dark")
            }
            _ => true, // no key means light mode
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Return the best initial theme index: Ghostty detection first, then
/// system appearance (Default Light index 8 vs Default Dark index 0).
pub fn detect_initial_theme() -> usize {
    detect_ghostty_theme().unwrap_or_else(|| if is_system_light() { 8 } else { 0 })
}

/// Query the terminal background colour via OSC 11.
///
/// Sends `\x1b]11;?\x07` and reads back `\x1b]11;rgb:RRRR/GGGG/BBBB\x1b\\`
/// (or BEL-terminated). Returns the RGB components as `(u8, u8, u8)`.
/// Must be called while the terminal is in raw mode (or briefly enters raw mode).
pub fn query_terminal_bg() -> Option<(u8, u8, u8)> {
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();

    // Save and set raw mode manually via termios.
    // SAFETY: zeroed termios is a valid initial state for tcgetattr to overwrite.
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a valid file descriptor (stdin); orig is a valid mutable pointer.
    if unsafe { libc::tcgetattr(fd, &raw mut orig) } != 0 {
        return None;
    }
    let mut raw = orig;
    raw.c_lflag &= !(libc::ICANON | libc::ECHO);
    raw.c_cc[libc::VMIN] = 0;
    raw.c_cc[libc::VTIME] = 1; // 100ms timeout per read
    // SAFETY: fd is valid; raw is a properly initialized termios struct.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const raw) } != 0 {
        return None;
    }

    // Send OSC 11 query.
    let _ = std::io::stdout().write_all(b"\x1b]11;?\x07");
    let _ = std::io::stdout().flush();

    // Read response with timeout.
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while std::time::Instant::now() < deadline {
        // SAFETY: fd is valid; byte buffer is valid and sized for 1 byte.
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
        if n <= 0 {
            if !buf.is_empty() {
                break;
            }
            continue;
        }
        buf.push(byte[0]);
        // Terminators: BEL (0x07) or ST (\x1b\\).
        if byte[0] == 0x07 || (buf.len() >= 2 && buf[buf.len() - 2] == 0x1b && byte[0] == b'\\') {
            break;
        }
    }

    // Restore terminal.
    // SAFETY: fd is valid; orig was saved by tcgetattr above.
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const orig) };

    // Parse: \x1b]11;rgb:RRRR/GGGG/BBBB<terminator>
    let response = String::from_utf8_lossy(&buf);
    let rgb_part = response.split("rgb:").nth(1)?;
    let rgb_part = rgb_part.trim_end_matches(['\x07', '\\', '\x1b']);
    let mut components = rgb_part.split('/');
    // OSC 11 returns 16-bit hex components; we only use the top 2 hex digits,
    // so values are guaranteed to fit in u8 (0..=255).
    #[allow(clippy::cast_possible_truncation)]
    let r = u16::from_str_radix(components.next()?.get(..2)?, 16).ok()? as u8;
    #[allow(clippy::cast_possible_truncation)]
    let g = u16::from_str_radix(components.next()?.get(..2)?, 16).ok()? as u8;
    #[allow(clippy::cast_possible_truncation)]
    let b = u16::from_str_radix(components.next()?.get(..2)?, 16).ok()? as u8;
    Some((r, g, b))
}

/// Compute whether an RGB colour is perceptually light.
fn is_light_bg(r: u8, g: u8, b: u8) -> bool {
    // Relative luminance approximation.
    let lum = 0.299 * f64::from(r) + 0.587 * f64::from(g) + 0.114 * f64::from(b);
    lum > 128.0
}

/// Nudge an RGB component by `delta` (positive = lighter, negative = darker),
/// clamped to 0..=255.
fn nudge(c: u8, delta: i16) -> u8 {
    // clamp(0, 255) guarantees the value is non-negative and fits in u8.
    #[allow(clippy::cast_sign_loss)]
    {
        (i16::from(c) + delta).clamp(0, 255) as u8
    }
}

/// Patch the two Default themes (indices 0 and 8) so their `bg`, `stripe_bg`,
/// `panel_bg`, and `highlight_bg` are derived from the actual terminal
/// background colour rather than hardcoded guesses.
pub fn patch_default_themes(themes: &mut [Theme], r: u8, g: u8, b: u8) {
    let light = is_light_bg(r, g, b);
    // Stripe: very subtle shift from bg.
    let stripe_d: i16 = if light { -8 } else { 6 };
    // Panel: slightly more shift.
    let panel_d: i16 = if light { -14 } else { 10 };
    // Highlight: strong shift.
    let highlight_d: i16 = if light { -30 } else { 20 };

    let bg = Color::Rgb(r, g, b);
    let stripe = Color::Rgb(nudge(r, stripe_d), nudge(g, stripe_d), nudge(b, stripe_d));
    let panel = Color::Rgb(nudge(r, panel_d), nudge(g, panel_d), nudge(b, panel_d));
    let highlight = Color::Rgb(
        nudge(r, highlight_d),
        nudge(g, highlight_d),
        nudge(b, highlight_d),
    );

    // Index 0 = Default (dark), Index 8 = Default Light.
    for idx in [0, 8] {
        if let Some(t) = themes.get_mut(idx) {
            t.bg = bg;
            t.stripe_bg = stripe;
            t.panel_bg = panel;
            t.highlight_bg = highlight;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_count() {
        assert_eq!(THEMES.len(), 16);
    }

    #[test]
    fn default_is_first() {
        assert_eq!(THEMES[0].name, "Default");
    }

    #[test]
    fn lookup_by_name() {
        assert_eq!(theme_index_by_name("Gruvbox"), 1);
        assert_eq!(theme_index_by_name("FFE Dark"), 6);
        assert_eq!(theme_index_by_name("Nonexistent"), 0);
    }

    #[test]
    fn all_unique_names() {
        let names: Vec<&str> = THEMES.iter().map(|t| t.name).collect();
        for (i, name) in names.iter().enumerate() {
            assert!(!names[..i].contains(name), "Duplicate: {name}");
        }
    }
}
