import { SEVERITY_STYLES } from '../lib/format'

export default function SeverityPill({ severity }) {
  const cls = SEVERITY_STYLES[severity] || SEVERITY_STYLES.low
  return (
    <span className={`inline-block text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded border ${cls}`}>
      {severity}
    </span>
  )
}
