import { useEffect, useMemo, useRef, useState } from 'react'

const KEYWORDS = /\b(public|private|protected|static|final|void|class|return|new|import|if|else|for|while|try|catch|fun|val|var|true|false|null|const|let|function|async|await|export|default|switch|case|break)\b/g
const XML_TAGS = /(&lt;\/?[\w:.-]+)/g
const XML_ATTRS = /([\w:-]+=)(?=&quot;|")/g
const STRINGS = /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g
const COMMENTS = /(\/\/.*$)/gm

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function buildSearchTokens(value, searchTerm) {
  if (!searchTerm) return { nextValue: value, tokens: [] }

  const matcher = new RegExp(searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi')
  const tokens = []
  let index = 0
  const nextValue = value.replace(matcher, match => {
    const token = `\uE000${index}\uE001`
    tokens.push({ token, value: match })
    index += 1
    return token
  })

  return { nextValue, tokens }
}

function restoreSearchTokens(value, tokens) {
  return tokens.reduce(
    (current, entry) => current.replaceAll(entry.token, `<mark class="code-search-hit">${entry.value}</mark>`),
    value,
  )
}

function highlightLine(line, language, searchTerm = '') {
  let value = escapeHtml(line)
  const { nextValue, tokens } = buildSearchTokens(value, searchTerm)
  value = nextValue

  if (language === 'xml' || language === 'plist') {
    value = value
      .replace(XML_TAGS, '<span class="code-token tag">$1</span>')
      .replace(XML_ATTRS, '<span class="code-token attr">$1</span>')
      .replace(/(&quot;[^&]*&quot;)/g, '<span class="code-token string">$1</span>')
    return restoreSearchTokens(value, tokens)
  }

  if (['java', 'kt', 'js', 'jsx', 'smali', 'json'].includes(language)) {
    value = value
      .replace(COMMENTS, '<span class="code-token comment">$1</span>')
      .replace(STRINGS, '<span class="code-token string">$1</span>')
      .replace(KEYWORDS, '<span class="code-token keyword">$1</span>')
      .replace(/(@\w+)/g, '<span class="code-token attr">$1</span>')
    return restoreSearchTokens(value, tokens)
  }

  return restoreSearchTokens(value, tokens)
}

export function inferLanguage(filePath = '', fallback = 'txt') {
  const extension = String(filePath).split('.').pop()?.toLowerCase()
  if (['xml', 'plist'].includes(extension)) return extension
  if (['java', 'kt', 'js', 'jsx', 'smali', 'json'].includes(extension)) return extension
  return fallback
}

export default function CodeBlockViewer({
  title,
  content = '',
  binaryInfo = null,
  language = 'txt',
  highlightedLines = [],
  focusLine = null,
  approximate = false,
  evidenceSource = '',
  evidence = [],
  evidenceIndex = 0,
  onNavigateEvidence,
  loading = false,
  error = '',
  meta = '',
  onClose,
}) {
  const [copied, setCopied] = useState(false)
  const [search, setSearch] = useState('')
  const [activeMatchIndex, setActiveMatchIndex] = useState(0)
  const lines = useMemo(() => String(content || '').split('\n'), [content])
  const highlightSet = useMemo(() => new Set(highlightedLines || []), [highlightedLines])
  const rowRefs = useRef(new Map())
  const codeBodyRef = useRef(null)
  // Center on the explicit focus line, else the middle of the highlighted range.
  const sortedHl = useMemo(() => [...(highlightedLines || [])].sort((a, b) => a - b), [highlightedLines])
  const primaryFocusLine = focusLine
    || (sortedHl.length ? sortedHl[Math.floor(sortedHl.length / 2)] : null)
  const searchMatches = useMemo(() => {
    if (!search.trim()) return []
    const query = search.toLowerCase()
    return lines.reduce((matches, line, index) => {
      if (line.toLowerCase().includes(query)) matches.push(index + 1)
      return matches
    }, [])
  }, [lines, search])

  const currentSearchLine = searchMatches[activeMatchIndex] || null

  useEffect(() => {
    if (!copied) return undefined
    const timer = window.setTimeout(() => setCopied(false), 1400)
    return () => window.clearTimeout(timer)
  }, [copied])

  useEffect(() => {
    setActiveMatchIndex(0)
  }, [search])

  useEffect(() => {
    if (loading || error || !lines.length) return undefined
    const targetLine = currentSearchLine || primaryFocusLine
    if (!targetLine) return undefined

    const timer = window.setTimeout(() => {
      rowRefs.current.get(targetLine)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }, 120)

    return () => window.clearTimeout(timer)
  }, [currentSearchLine, error, lines.length, loading, primaryFocusLine])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content || '')
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  const jumpToMatch = direction => {
    if (!searchMatches.length) return
    setActiveMatchIndex(current => {
      const next = direction === 'prev'
        ? (current - 1 + searchMatches.length) % searchMatches.length
        : (current + 1) % searchMatches.length
      return next
    })
  }

  const minimapMarkers = useMemo(() => {
    const total = Math.max(lines.length, 1)
    const markerMap = new Map()

    highlightedLines.forEach(lineNumber => {
      markerMap.set(`highlight-${lineNumber}`, {
        top: `${(lineNumber / total) * 100}%`,
        tone: 'highlight',
        lineNumber,
      })
    })

    searchMatches.forEach(lineNumber => {
      markerMap.set(`search-${lineNumber}`, {
        top: `${(lineNumber / total) * 100}%`,
        tone: lineNumber === currentSearchLine ? 'active-search' : 'search',
        lineNumber,
      })
    })

    return [...markerMap.values()]
  }, [currentSearchLine, highlightedLines, lines.length, searchMatches])

  return (
    <div className="code-viewer">
      <div className="code-viewer__header">
        <div>
          <div className="code-viewer__title">{title || 'Source viewer'}</div>
          {meta ? <div className="code-viewer__meta">{meta}</div> : null}
        </div>

        <div className="code-viewer__actions">
          <button type="button" className="button button--ghost button--small" onClick={handleCopy}>
            {copied ? 'Copied ✓' : 'Copy'}
          </button>
          {onClose ? (
            <button type="button" className="button button--ghost button--small" onClick={onClose}>
              Close
            </button>
          ) : null}
        </div>
      </div>

      {(approximate || evidenceSource || evidence.length > 1) ? (
        <div className="code-viewer__evidence">
          <span className={`code-viewer__line-badge${approximate ? ' is-approx' : ''}`}>
            {sortedHl.length
              ? `${approximate ? '≈' : ''} ${sortedHl.length > 1 ? `lines ${sortedHl[0]}–${sortedHl[sortedHl.length - 1]}` : `line ${sortedHl[0]}`}`.trim()
              : 'line —'}
          </span>
          {approximate ? <span className="code-viewer__approx-note">approximate — resolved by deterministic search, not a declared line</span> : null}
          {evidenceSource ? <span className="code-viewer__evsrc">source: {evidenceSource}</span> : null}
          {evidence.length > 1 && onNavigateEvidence ? (
            <div className="code-viewer__evnav">
              <button
                type="button"
                className="button button--ghost button--small"
                onClick={() => onNavigateEvidence(Math.max(0, evidenceIndex - 1))}
                disabled={evidenceIndex <= 0}
              >
                ‹ Prev evidence
              </button>
              <span className="code-viewer__evcount">Evidence {evidenceIndex + 1}/{evidence.length}</span>
              <button
                type="button"
                className="button button--ghost button--small"
                onClick={() => onNavigateEvidence(Math.min(evidence.length - 1, evidenceIndex + 1))}
                disabled={evidenceIndex >= evidence.length - 1}
              >
                Next evidence ›
              </button>
            </div>
          ) : null}
        </div>
      ) : null}

      {binaryInfo ? (
        <div className="code-viewer__binary">
          <div className="code-viewer__binary-head">
            <span className="code-viewer__binary-kind">{binaryInfo.label || 'Compiled binary'}</span>
            <span className="code-viewer__binary-name" title={binaryInfo.name}>{binaryInfo.name}</span>
          </div>
          {binaryInfo.note ? <p className="code-viewer__binary-note">{binaryInfo.note}</p> : null}

          {(binaryInfo.details || []).length || binaryInfo.size ? (
            <dl className="code-viewer__binary-grid">
              {binaryInfo.size ? (<div><dt>Size</dt><dd>{binaryInfo.size}</dd></div>) : null}
              {(binaryInfo.details || []).map((d, i) => (
                <div key={i}><dt>{d.label}</dt><dd>{d.value}</dd></div>
              ))}
            </dl>
          ) : null}

          {(binaryInfo.protections || []).length ? (
            <div className="code-viewer__binary-block">
              <div className="code-viewer__binary-subhead">Binary protections</div>
              <div className="code-viewer__binary-chips">
                {binaryInfo.protections.map((p, i) => (
                  <span key={i} className={`code-viewer__binary-chip${p.present ? ' is-on' : ' is-off'}`}>
                    {p.present ? '✓' : '✕'} {p.label}
                  </span>
                ))}
              </div>
            </div>
          ) : null}

          {(binaryInfo.recoverable || []).length ? (
            <div className="code-viewer__binary-block">
              <div className="code-viewer__binary-subhead">Recoverable metadata</div>
              <div className="code-viewer__binary-chips">
                {binaryInfo.recoverable.map((r, i) => (
                  <span key={i} className="code-viewer__binary-chip">{r}</span>
                ))}
              </div>
            </div>
          ) : null}

          {(binaryInfo.linked_libraries || []).length ? (
            <div className="code-viewer__binary-block">
              <div className="code-viewer__binary-subhead">Linked libraries ({binaryInfo.linked_libraries.length})</div>
              <ul className="code-viewer__binary-list">
                {binaryInfo.linked_libraries.slice(0, 24).map((l, i) => <li key={i}>{l}</li>)}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}

      {!binaryInfo ? (<>
      <div className="code-viewer__toolbar">
        <label className="code-viewer__search">
          <input
            value={search}
            onChange={event => setSearch(event.target.value)}
            onKeyDown={event => {
              if (event.key === 'Enter') {
                event.preventDefault()
                jumpToMatch(event.shiftKey ? 'prev' : 'next')
              }
            }}
            placeholder="Search in file…"
          />
        </label>

        <div className="code-viewer__search-meta">
          {search.trim()
            ? `${searchMatches.length ? `${activeMatchIndex + 1}/${searchMatches.length}` : '0 matches'}`
            : primaryFocusLine
              ? `Focused line ${primaryFocusLine}`
              : 'Search ready'}
        </div>

        <div className="code-viewer__toolbar-actions">
          <button type="button" className="button button--ghost button--small" onClick={() => jumpToMatch('prev')} disabled={!searchMatches.length}>
            Prev
          </button>
          <button type="button" className="button button--ghost button--small" onClick={() => jumpToMatch('next')} disabled={!searchMatches.length}>
            Next
          </button>
        </div>
      </div>

      <div className="code-viewer__body" ref={codeBodyRef}>
        {loading ? (
          <div className="empty-state empty-state--dark">Loading source…</div>
        ) : null}

        {!loading && error ? (
          <div className="empty-state empty-state--dark">{error}</div>
        ) : null}

        {!loading && !error ? (
          <div className="code-viewer__layout">
            <table className="code-table">
              <tbody>
                {lines.map((line, index) => {
                  const lineNumber = index + 1
                  const highlighted = highlightSet.has(lineNumber)
                  const searchHit = searchMatches.includes(lineNumber)
                  const activeSearchHit = currentSearchLine === lineNumber
                  const focusLine = primaryFocusLine === lineNumber

                  return (
                    <tr
                      key={lineNumber}
                      ref={node => {
                        if (node) rowRefs.current.set(lineNumber, node)
                        else rowRefs.current.delete(lineNumber)
                      }}
                      className={[
                        highlighted ? 'is-highlighted' : '',
                        searchHit ? 'is-search-hit' : '',
                        activeSearchHit ? 'is-active-search-hit' : '',
                        focusLine ? 'is-focus-line' : '',
                      ].filter(Boolean).join(' ')}
                    >
                      <td className="code-table__line">
                        <span>{lineNumber}</span>
                      </td>
                      <td
                        className="code-table__content"
                        dangerouslySetInnerHTML={{ __html: highlightLine(line || ' ', language, search.trim()) }}
                      />
                    </tr>
                  )
                })}
              </tbody>
            </table>

            <div className="code-minimap" aria-hidden="true">
              {minimapMarkers.map(marker => (
                <button
                  key={`${marker.tone}-${marker.lineNumber}`}
                  type="button"
                  className={`code-minimap__marker code-minimap__marker--${marker.tone}`}
                  style={{ top: marker.top }}
                  onClick={() => rowRefs.current.get(marker.lineNumber)?.scrollIntoView({ behavior: 'smooth', block: 'center' })}
                />
              ))}
            </div>
          </div>
        ) : null}
      </div>
      </>) : null}
    </div>
  )
}
