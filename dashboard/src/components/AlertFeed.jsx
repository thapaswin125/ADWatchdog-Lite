import SeverityPill from './SeverityPill'
import { fmtDateTime } from '../lib/format'

export default function AlertFeed({ alerts, selectedId, onSelect }) {
  return (
    <div className="flex flex-col h-full">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <div>
          <div className="text-sm uppercase tracking-wider text-slate-400">Live Alert Feed</div>
          <div className="text-xs text-slate-500 mt-1">Newest fired detections appear on top.</div>
        </div>
        <div className="text-xs text-slate-500 font-mono">{alerts.length} alert(s)</div>
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin px-4 py-3 space-y-2">
        {alerts.length === 0 && (
          <div className="text-sm text-slate-500 italic mt-8 text-center">
            No alerts yet. Run a simulation from the left panel.
          </div>
        )}
        {alerts.map((a) => {
          const selected = a.id === selectedId
          const conf = Math.round((a.confidence || 0) * 100)
          return (
            <button
              key={a.id}
              onClick={() => onSelect(a.id)}
              className={`w-full text-left bg-panel border rounded-lg p-3 transition-colors ${
                selected ? 'border-cyan-500 ring-1 ring-cyan-500/30' : 'border-border hover:border-slate-600'
              }`}
            >
              <div className="flex items-center gap-2">
                <SeverityPill severity={a.severity} />
                <span className="font-mono text-xs text-slate-500">{a.rule_id}</span>
                <span className="ml-auto text-xs text-slate-500">{fmtDateTime(a.first_seen)}</span>
              </div>

              <div className="mt-2 font-semibold text-slate-100 leading-snug">
                {a.rule_name}
              </div>

              <div className="mt-1 text-xs text-slate-400 font-mono">
                {a.mitre_id} · {a.matched_event_count} events · {a.affected_accounts?.length || 0} accounts
              </div>

              <div className="mt-2">
                <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                  <span>Confidence</span>
                  <span className="font-mono">{conf}%</span>
                </div>
                <div className="h-1 rounded bg-border overflow-hidden">
                  <div className="h-full bg-cyan-400" style={{ width: `${conf}%` }} />
                </div>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}
