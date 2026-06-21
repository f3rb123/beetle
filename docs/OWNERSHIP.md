# Ownership Classification

> Skeleton — Phase 11.5. Expand with package-mapping examples before GA.

## What it answers

"Whose code is this — the app's, a third-party SDK's, or the platform's?" — so the
default report shows application-owned issues and suppresses library/framework noise.

## Where it lives

`backend/analyzers/finding_model.py`:
- `classify_ownership(path, app_package)` → coarse `APP / LIBRARY / SYSTEM / UNKNOWN`
- `classify_ownership_label(...)` → fine label `APPLICATION / THIRD_PARTY_LIBRARY /
  GOOGLE_SDK / FIREBASE / JETPACK / ANDROID_FRAMEWORK / UNKNOWN`
- `resolve_finding_ownership(...)` → authoritative `(coarse, label, owner_package)`

## How it decides

1. Derive a dotted package from the source path or class reference.
2. App package prefix → APPLICATION.
3. Known SDK/framework prefix tables → library/framework label.
4. Manifest/component/app-config findings with no path → APPLICATION.
5. Obfuscated / underivable → UNKNOWN (kept visible, not suppressed).

## TODO

- [ ] Document the SDK prefix tables and how to extend them
- [ ] Examples of UNKNOWN (obfuscated) handling
- [ ] Secret-specific ownership collapse (see [[SECRET_INTELLIGENCE]])
