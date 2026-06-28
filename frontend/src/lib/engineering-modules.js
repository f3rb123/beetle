/**
 * Engineering Workspace — module configuration model (Beetle 2.0, Phase 2.0).
 *
 * The single source of truth for every capability the workspace surfaces. The grid
 * is a pure projection of this list, so the UI never hardcodes navigation: a module
 * is enabled simply by flipping its `status` to AVAILABLE and giving it a launch
 * descriptor (`accept` / `platform` for upload modules, or a future `route`).
 *
 * Each module:
 *   id          stable key
 *   name        display name
 *   icon        a lucide-react component
 *   status      MODULE_STATUS.AVAILABLE | COMING_SOON
 *   description short one-liner shown on the card
 *   capability  planned/primary capability (shown on Coming Soon cards)
 *   eta         expected status text (Coming Soon cards)
 *   accept      file-input filter for upload modules (e.g. ".apk")
 *   platform    "android" | "ios" — for the upload workflow hint
 *
 * To ship a future module: change its `status` to AVAILABLE and add a launch
 * descriptor. No component, navigation, or layout changes are required.
 */
import {
  Smartphone, Apple, Layers, Atom, ScanSearch, GitBranch,
  BrainCircuit, Puzzle, Building2,
} from 'lucide-react'

export const MODULE_STATUS = Object.freeze({
  AVAILABLE: 'available',
  COMING_SOON: 'coming-soon',
})

export const ENGINEERING_MODULES = [
  // ── Available today — launch the existing upload + analysis workflow ──────────
  {
    id: 'android',
    name: 'Android Security Analysis',
    icon: Smartphone,
    status: MODULE_STATUS.AVAILABLE,
    description: 'Static analysis of Android APKs — secrets, SAST, attack chains, network & manifest intelligence.',
    capability: 'APK decompilation, finding fusion, evidence selection.',
    accept: '.apk',
    platform: 'android',
  },
  {
    id: 'ios',
    name: 'iOS Security Analysis',
    icon: Apple,
    status: MODULE_STATUS.AVAILABLE,
    description: 'Static analysis of iOS IPAs — secrets, SAST, Mach-O & plist intelligence, attack chains.',
    capability: 'IPA inspection, finding fusion, evidence selection.',
    accept: '.ipa',
    platform: 'ios',
  },

  // ── Coming soon — visually complete, non-functional ──────────────────────────
  {
    id: 'flutter',
    name: 'Flutter Security Intelligence',
    icon: Layers,
    status: MODULE_STATUS.COMING_SOON,
    description: 'Dart/Flutter snapshot analysis for cross-platform applications.',
    capability: 'Dart AOT snapshot parsing, Flutter secret & API surface analysis.',
    eta: 'Planned',
  },
  {
    id: 'react-native',
    name: 'React Native Security Intelligence',
    icon: Atom,
    status: MODULE_STATUS.COMING_SOON,
    description: 'JavaScript bundle and native-bridge analysis for React Native apps.',
    capability: 'Hermes/JSC bundle inspection, bridge attack-surface mapping.',
    eta: 'Planned',
  },
  {
    id: 'semgrep',
    name: 'Semgrep Integration',
    icon: ScanSearch,
    status: MODULE_STATUS.COMING_SOON,
    description: 'Policy-as-code SAST rules fused natively into Beetle findings.',
    capability: 'Semgrep rulepacks as a first-class detection source.',
    eta: 'Planned',
  },
  {
    id: 'cicd',
    name: 'CI/CD Security',
    icon: GitBranch,
    status: MODULE_STATUS.COMING_SOON,
    description: 'Automated scanning in build pipelines with policy gating.',
    capability: 'Pull-request checks, policy gates, SARIF export to CI.',
    eta: 'Planned',
  },
  {
    id: 'ai',
    name: 'AI Security Intelligence',
    icon: BrainCircuit,
    status: MODULE_STATUS.COMING_SOON,
    description: 'LLM-assisted triage, explanations and remediation guidance.',
    capability: 'Finding explanation, false-positive review, fix guidance.',
    eta: 'Planned',
  },
  {
    id: 'plugin-sdk',
    name: 'Plugin SDK',
    icon: Puzzle,
    status: MODULE_STATUS.COMING_SOON,
    description: 'Build and register custom detection engines and rule packs.',
    capability: 'Detection-source SDK, custom rules, fusion hooks.',
    eta: 'Planned',
  },
  {
    id: 'enterprise',
    name: 'Enterprise Dashboard',
    icon: Building2,
    status: MODULE_STATUS.COMING_SOON,
    description: 'Organization-wide posture, trends and team workflows.',
    capability: 'Fleet view, SSO, RBAC, historical trend analytics.',
    eta: 'Planned',
  },
]

export const isModuleAvailable = (m) => m?.status === MODULE_STATUS.AVAILABLE
