export const SEVERITY_STYLES = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/40',
  high:     'bg-orange-500/20 text-orange-300 border-orange-500/40',
  medium:   'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
  low:      'bg-slate-500/20 text-slate-300 border-slate-500/40',
}

export function fmtTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour12: false })
}

export function fmtDateTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleString([], { hour12: false })
}
