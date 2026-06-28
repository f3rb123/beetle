/**
 * Engineering Workspace — module launcher grid (Beetle 2.0, Phase 2.0).
 *
 * A pure projection of `ENGINEERING_MODULES`: Available modules launch the existing
 * upload workflow via `onLaunch`; Coming Soon modules are visually complete but
 * non-functional and reveal an inline "Available in a future release" message on
 * click. No navigation is hardcoded here — behavior is driven entirely by a module's
 * `status`, so enabling a future module is a one-field config change.
 */
import { useState } from 'react'
import { ENGINEERING_MODULES, MODULE_STATUS, isModuleAvailable } from '../lib/engineering-modules.js'

function ModuleCard({ module, active, onSelect, showNotice }) {
  const Icon = module.icon
  const available = isModuleAvailable(module)
  return (
    <button
      type="button"
      className={`ew-card ${available ? 'ew-card--ready' : 'ew-card--soon'}${active ? ' is-active' : ''}`}
      onClick={() => onSelect(module)}
      aria-disabled={available ? 'false' : 'true'}
      aria-label={`${module.name} — ${available ? 'available' : 'coming soon'}`}
    >
      <span className="ew-card__top">
        <span className="ew-card__icon">{Icon ? <Icon size={20} aria-hidden="true" /> : null}</span>
        <span className={`ew-card__badge ew-card__badge--${available ? 'ready' : 'soon'}`}>
          {available ? 'Available' : 'Coming Soon'}
        </span>
      </span>

      <span className="ew-card__name">{module.name}</span>
      <span className="ew-card__desc">{module.description}</span>

      {!available ? (
        <span className="ew-card__meta">
          {module.capability ? <span className="ew-card__capability">{module.capability}</span> : null}
          <span className="ew-card__eta">{module.eta || 'Planned'}</span>
        </span>
      ) : null}

      {!available && showNotice ? (
        <span className="ew-card__notice" role="status">Available in a future release</span>
      ) : null}
    </button>
  )
}

export default function EngineeringWorkspace({ activeModuleId, onLaunch }) {
  // Which Coming Soon card is currently showing its "future release" notice.
  const [noticeId, setNoticeId] = useState(null)

  const available = ENGINEERING_MODULES.filter(isModuleAvailable)
  const upcoming = ENGINEERING_MODULES.filter((m) => m.status !== MODULE_STATUS.AVAILABLE)

  const handleSelect = (module) => {
    if (isModuleAvailable(module)) {
      setNoticeId(null)
      onLaunch?.(module)
    } else {
      // Toggle the inline message; non-functional by design.
      setNoticeId((prev) => (prev === module.id ? null : module.id))
    }
  }

  return (
    <section className="ew" aria-label="Engineering Workspace">
      <header className="ew__head">
        <h2 className="ew__title">Engineering Workspace</h2>
        <p className="ew__subtitle">Choose a capability to begin. More modules are on the way.</p>
      </header>

      <div className="ew__group-label">Available</div>
      <div className="ew__grid">
        {available.map((m) => (
          <ModuleCard key={m.id} module={m} active={activeModuleId === m.id} onSelect={handleSelect} />
        ))}
      </div>

      <div className="ew__group-label">Coming soon</div>
      <div className="ew__grid ew__grid--soon">
        {upcoming.map((m) => (
          <ModuleCard key={m.id} module={m} showNotice={noticeId === m.id} onSelect={handleSelect} />
        ))}
      </div>
    </section>
  )
}
