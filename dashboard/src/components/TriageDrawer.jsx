import { useState, useEffect } from 'react'
import { marked } from 'marked'
import SeverityPill from './SeverityPill'
import { fmtDateTime } from '../lib/format'
import { api } from '../lib/api'

function EventRow({ ev }) {
  const target =
    ev.target_spn || ev.target_account || ev.new_spn_value || ev.requesting_machine || ''
  return (
    <div className="border-b border-border/50 py-1.5">
      <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px]">
        <span className="text-slate-500">{ev.timestamp}</span>
        <span className="text-cyan-300">{ev.event_type}</span>
        <span className="text-slate-300">src={ev.src_ip}</span>
        <span className="text-slate-300">user={ev.username || ev.actor_username || '?'}</span>
        {target && <span className="text-slate-400">target={target}</span>}
        {ev.auth_result && (
          <span className={ev.auth_result === 'FAILURE' ? 'text-red-400' : 'text-emerald-400'}>
            {ev.auth_result}
          </span>
        )}
      </div>
    </div>
  )
}

export default function TriageDrawer({ alert, onRunbookGenerated }) {
  const [runbook, setRunbook] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    setRunbook(alert?.runbook_md || null)
    setError(null)
  }, [alert?.id])

  if (!alert) {
    return (
      <div className="flex flex-col h-full">
        <div className="px-4 py-3 border-b border-border">
          <div className="text-sm uppercase tracking-wider text-slate-400">Triage Drawer</div>
          <div className="text-xs text-slate-500 mt-1">Select an alert to see the details.</div>
        </div>
        <div className="flex-1 flex items-center justify-center text-sm text-slate-500 italic">
          No alert selected.
        </div>
      </div>
    )
  }

  async function handleGenerate() {
    setLoading(true)
    setError(null)
    try {
      const res = await api.runbook(alert.id)
      setRunbook(res.runbook_md)
      onRunbookGenerated?.()
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  function handleDownload() {
    if (!runbook) return
    const blob = new Blob([runbook], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${alert.rule_id}_${alert.id.slice(0, 8)}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const events = (alert.events || []).slice(0, 10)

  return (
    <div className="flex flex-col h-full">
      <div className="px-4 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <SeverityPill severity={alert.severity} />
          <span className="font-mono text-xs text-slate-500">{alert.rule_id}</span>
          <span className="ml-auto text-xs text-slate-500 font-mono">{alert.mitre_id}</span>
        </div>
        <div className="mt-1 font-semibold text-slate-100 leading-tight">{alert.rule_name}</div>
        <div className="mt-1 text-xs text-slate-400">{alert.mitre_technique}</div>
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin px-4 py-3 space-y-4">
        <section>
          <div className="text-xs uppercase tracking-wider text-slate-400 mb-2">Metadata</div>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
            <dt className="text-slate-500">First seen</dt>
            <dd className="font-mono text-slate-200">{fmtDateTime(alert.first_seen)}</dd>
            <dt className="text-slate-500">Last seen</dt>
            <dd className="font-mono text-slate-200">{fmtDateTime(alert.last_seen)}</dd>
            <dt className="text-slate-500">Events matched</dt>
            <dd className="font-mono text-slate-200">{alert.matched_event_count}</dd>
            <dt className="text-slate-500">Confidence</dt>
            <dd className="font-mono text-slate-200">{Math.round(alert.confidence * 100)}%</dd>
            <dt className="text-slate-500">Source IPs</dt>
            <dd className="font-mono text-slate-200 truncate">{alert.src_ips?.join(', ') || '—'}</dd>
            <dt className="text-slate-500">Accounts</dt>
            <dd className="font-mono text-slate-200 truncate" title={alert.affected_accounts?.join(', ')}>
              {alert.affected_accounts?.join(', ') || '—'}
            </dd>
          </dl>
        </section>

        <section>
          <div className="text-xs uppercase tracking-wider text-slate-400 mb-2">
            Matched Events ({events.length} of {alert.events?.length || 0})
          </div>
          <div className="bg-panel border border-border rounded-lg p-2 font-mono">
            {events.length === 0 && <div className="text-xs text-slate-500">No events.</div>}
            {events.map((ev) => <EventRow key={ev.event_id} ev={ev} />)}
          </div>
        </section>

        <section>
          <div className="flex items-center gap-2 mb-2">
            <div className="text-xs uppercase tracking-wider text-slate-400">AI Triage Runbook</div>
            <div className="ml-auto flex gap-2">
              <button
                onClick={handleGenerate}
                disabled={loading}
                className="text-xs px-3 py-1.5 rounded bg-cyan-500 text-ink font-semibold hover:bg-cyan-400 disabled:opacity-40"
              >
                {loading ? 'Generating…' : runbook ? 'Regenerate' : 'Generate Runbook'}
              </button>
              <button
                onClick={handleDownload}
                disabled={!runbook}
                className="text-xs px-3 py-1.5 rounded border border-border text-slate-300 hover:border-cyan-500 hover:text-cyan-300 disabled:opacity-40"
              >
                Download .md
              </button>
            </div>
          </div>
          {error && (
            <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded p-2 mb-2">
              {error}
            </div>
          )}
          {runbook ? (
            <div
              className="markdown bg-panel border border-border rounded-lg p-4 text-sm"
              dangerouslySetInnerHTML={{ __html: marked.parse(runbook) }}
            />
          ) : (
            <div className="text-xs text-slate-500 italic">
              No runbook yet. Click <span className="text-cyan-400">Generate Runbook</span> to call Claude.
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
