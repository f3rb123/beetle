// Single source of truth for Beetle brand artwork so every page stays in sync.
//
// - blackMark: the BLACK hexagon mark. Use on LIGHT surfaces (dashboards,
//   sidebars, light cards) where it reads directly without a tile.
// - whiteMark: the WHITE hexagon mark. Built for dark UIs — must be seated on a
//   dark tile (e.g. `background: var(--auth-ink)`) so it reads on light pages.
//
// beetle-logo.png (the old white full lockup) is intentionally NOT exported: it
// was invisible on Beetle's light surfaces and is superseded by blackMark.
import blackMark from './beetle_black_logo.png'
import whiteMark from './beetle-icon.png'

export { blackMark, whiteMark }
