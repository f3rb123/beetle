export default function BrandLogo({ animated = false, size = 'default', showWordmark = true, subtitle = 'Mobile Static Security Workspace' }) {
  return (
    <div className={`brand-lockup brand-lockup--${size}`}>
      <div className={`brand-mark${animated ? ' brand-mark--animated' : ''}`} aria-hidden="true">
        <span className="brand-mark__ring" />
        <span className="brand-mark__ring brand-mark__ring--offset" />
        <span className="brand-mark__core">C</span>
      </div>

      {showWordmark ? (
        <div className="brand-lockup__text">
          <div className="brand-lockup__title">Cortex</div>
          <div className="brand-lockup__subtitle">{subtitle}</div>
        </div>
      ) : null}
    </div>
  )
}
