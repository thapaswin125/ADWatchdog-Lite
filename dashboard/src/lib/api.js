const BASE = ''

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status} ${text}`)
  }
  return res.json()
}

export const api = {
  scenarios: () => req('/api/scenarios'),
  alerts: () => req('/api/alerts'),
  alert: (id) => req(`/api/alerts/${id}`),
  stats: () => req('/api/stats'),
  simulate: (scenario_id, stealth) =>
    req('/api/simulate', { method: 'POST', body: JSON.stringify({ scenario_id, stealth }) }),
  runbook: (id) =>
    req(`/api/alerts/${id}/runbook`, { method: 'POST' }),
}
