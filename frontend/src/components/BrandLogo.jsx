import { blackMark as beetleLogo, whiteMark as beetleIcon } from '../assets/brandLogos.js'

export default function BrandLogo({ animated = false, size = 'default', showWordmark = true, subtitle = 'Mobile Static Security Workspace' }) {
  // beetle_black_logo.png is the full lockup (wordmark + tagline) on the BLACK
  // wordmark variant so it stays visible on Beetle's light surfaces (the white
  // lockup was invisible on the dashboard/header light background). beetle-icon.png
  // is the standalone mark used for
  // compact / sidebar / icon-only contexts, where the wordmark and subtitle are
  // rendered as text beside it to preserve the existing layout.
  const useFullLockup = size === 'default' && showWordmark

  if (useFullLockup) {
    return (
      <div className={`brand-lockup brand-lockup--${size}`}>
        <img
          src={beetleLogo}
          alt="Beetle"
          className={`brand-logo-full${animated ? ' brand-mark--animated' : ''}`}
        />
      </div>
    )
  }

  return (
    <div className={`brand-lockup brand-lockup--${size}`}>
      <div className={`brand-mark${animated ? ' brand-mark--animated' : ''}`} aria-hidden="true">
        <img src={beetleIcon} alt="" className="brand-mark__img" />
      </div>

      {showWordmark ? (
        <div className="brand-lockup__text">
          <div className="brand-lockup__title">Beetle</div>
          <div className="brand-lockup__subtitle">{subtitle}</div>
        </div>
      ) : null}
    </div>
  )
}
