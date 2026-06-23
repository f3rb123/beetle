// AI provider abstraction — Phase 11.75 Task 8.
// The workspace is provider-agnostic: Claude is NOT hardcoded. Providers are a
// registry; `runAssist` dispatches to a configured backend endpoint when one is
// available, otherwise it falls back to the deterministic analyst intelligence
// the backend already generated (analyst_explanation / analyst_summary). This
// keeps the AI Assistant useful offline and ready to wire any LLM later.
import { apiFetch } from './auth.js'

export const AI_PROVIDERS = [
  { id: 'claude', name: 'Claude (Anthropic)', models: ['claude-haiku', 'claude-sonnet', 'claude-opus'] },
  { id: 'openai', name: 'OpenAI', models: ['gpt-4o-mini', 'gpt-4o'] },
  { id: 'gemini', name: 'Google Gemini', models: ['gemini-1.5-flash', 'gemini-1.5-pro'] },
  { id: 'deepseek', name: 'DeepSeek', models: ['deepseek-chat', 'deepseek-reasoner'] },
  { id: 'ollama', name: 'Ollama (local)', models: ['llama3', 'qwen2.5', 'mistral'] },
]

export const AI_ACTIONS = [
  { id: 'explain_finding', label: 'Explain Finding', needs: 'finding' },
  { id: 'explain_chain', label: 'Explain Attack Chain', needs: 'chain' },
  { id: 'generate_remediation', label: 'Generate Fix', needs: 'finding' },
  { id: 'executive_summary', label: 'Executive Summary', needs: 'results' },
  { id: 'developer_summary', label: 'Developer Summary', needs: 'results' },
  { id: 'explain_risk', label: 'Explain Risk', needs: 'finding' },
  { id: 'secure_example', label: 'Generate Secure Example', needs: 'finding' },
]

// Deterministic fallback that renders from the backend's analyst intelligence.
function localAssist(action, ctx) {
  const f = ctx.finding || {}
  const ex = f.analyst_explanation || {}
  const r = ctx.results || {}
  switch (action) {
    case 'explain_finding':
      return [ex.why_it_matters, ex.attack_scenario].filter(Boolean).join('\n\n')
        || f.description || 'No explanation available for this finding.'
    case 'explain_risk':
      return [ex.impact, ex.confidence_reason].filter(Boolean).join('\n\n')
        || 'Risk context is not available for this finding.'
    case 'generate_remediation': {
      const rem = ex.remediation || {}
      return [rem.summary || f.recommendation,
        (rem.masvs || f.masvs) ? `MASVS: ${rem.masvs || f.masvs}` : '',
        (rem.owasp || f.owasp) ? `OWASP: ${rem.owasp || f.owasp}` : ''].filter(Boolean).join('\n')
        || 'No remediation guidance available.'
    }
    case 'explain_chain': {
      const c = ctx.chain || {}
      const cex = c.analyst_explanation || {}
      const steps = (c.components || []).map(s => s.label).filter(Boolean).join(' → ')
      return [cex.why_it_matters || c.summary, steps ? `Path: ${steps}` : '', cex.impact].filter(Boolean).join('\n\n')
        || 'No attack chain explanation available.'
    }
    case 'executive_summary': {
      const a = r.analyst_summary || {}
      const sev = r.severity_summary || {}
      const lines = [
        `${r.app_name || 'This app'} — security posture summary.`,
        `Findings: ${(r.findings || []).length} (critical ${sev.critical || 0}, high ${sev.high || 0}).`,
        r.trust_score ? `Trust score: ${r.trust_score.score} (${r.trust_score.rating}).` : '',
        r.masvs_summary ? `MASVS overall ${r.masvs_summary.overall_score} — weakest ${r.masvs_summary.weakest_category}.` : '',
        (a.top_risks || []).length ? `Top risk: ${a.top_risks[0].title}.` : '',
        (a.most_exploitable_chains || []).length ? `Most exploitable: ${a.most_exploitable_chains[0].title}.` : '',
      ]
      return lines.filter(Boolean).join('\n')
    }
    case 'developer_summary': {
      const apps = (r.findings || []).filter(x => (x.ownership_label || x.ownership) === 'APPLICATION' || !x.ownership_label)
      const top = apps.slice(0, 6).map(x => {
        const fix = (x.analyst_explanation || {}).developer_fix || x.recommendation || 'review'
        return `• [${x.severity}] ${x.title}\n    fix: ${fix}`
      })
      return [`Developer action list for ${r.app_name || 'this app'} (application-owned issues):`, ...top].filter(Boolean).join('\n')
    }
    case 'secure_example': {
      const rem = ex.remediation || {}
      return `// Secure pattern guidance for: ${f.title || 'finding'}\n// ${rem.summary || f.recommendation || 'Apply platform secure-coding guidance.'}\n//\n// A concrete code example requires a connected LLM provider (configure one above).`
    }
    default:
      return 'Unsupported action.'
  }
}

// Whether a live backend AI endpoint is configured (kept off by default so the
// page never errors). Wire this to a real provider gateway when available.
export function liveAiEnabled() {
  return false
}

// ── Phase 11.97: Finding Drawer AI actions (backed by /api/ai/action) ────────
// Provider-agnostic: the UI never contains provider-specific code. It lists
// providers from the backend, lets the user pick one, and posts an action +
// finding evidence. The backend calls the provider (or returns a deterministic,
// evidence-only result when none is configured). Responses are cached here per
// session AND in the backend, so repeats reuse the previous response.
export const FINDING_AI_ACTIONS = [
  { id: 'explain', label: 'Explain' },
  { id: 'verify', label: 'Verify' },
  { id: 'worth_testing', label: 'Worth Testing?' },
  { id: 'generate_poc', label: 'Generate PoC' },
  { id: 'generate_fix', label: 'Generate Fix' },
]

export async function fetchAiProviders() {
  try {
    const r = await apiFetch('/api/ai/providers')
    if (r.ok) return await r.json()
  } catch { /* offline / unauth */ }
  return { providers: [], any_available: false }
}

const _actionCache = new Map()

function _findingId(f = {}) {
  return f.id || f.canonical_id || `${f.title || f.name || ''}|${f.file_path || ''}|${f.line || ''}`
}

export async function runFindingAction({ action, provider, model, finding, results }) {
  const key = `${action}|${provider || 'auto'}|${model || ''}|${action === 'summary' ? (results?.scan_id || '') : _findingId(finding)}`
  if (_actionCache.has(key)) return { ..._actionCache.get(key), cached: true }
  let out = null
  try {
    const body = action === 'summary'
      ? { action, provider, model, results }
      : { action, provider, model, finding }
    const r = await apiFetch('/api/ai/action', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    })
    if (r.ok) out = await r.json()
  } catch { /* network/offline */ }
  if (!out) out = { error: 'AI action unavailable', action, mode: 'error', provider: provider || '', result: {} }
  _actionCache.set(key, out)
  return out
}

export async function runAssist({ provider, model, action, context }) {
  // Provider abstraction seam: when a live gateway is enabled, POST to it.
  if (liveAiEnabled()) {
    try {
      const resp = await apiFetch('/api/ai/assist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, model, action, context: context.brief || {} }),
      })
      if (resp.ok) { const data = await resp.json(); return { text: data.text, live: true, provider } }
    } catch { /* fall through to local */ }
  }
  return { text: localAssist(action, context), live: false, provider }
}
