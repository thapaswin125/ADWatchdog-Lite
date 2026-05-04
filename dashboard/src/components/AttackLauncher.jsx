import { useState } from 'react'
import SeverityPill from './SeverityPill'

export default function AttackLauncher({ scenarios, onRun, running, coverage }) {
  const [stealth, setStealth] = useState({})

  const setForId = (id, val) =>
    setStealth((s) => ({ ...s, [id]: val }))

  return (
    <div className="flex flex-col h-full">
      <div className="px-4 py-3 border-b border-border">
        <div className="text-sm uppercase tracking-wider text-slate-400">
          Attack Launcher
        </div>
        <div className="text-xs text-slate-500 mt-1">
          Pick a scenario, choose its noise level, fire it.
        </div>
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin px-4 py-3 space-y-3">
        {scenarios.map((sc) => {
          const s = stealth[sc.id] ?? 0
          const isRunning = running === sc.id
          return (
            <div
              key={sc.id}
              className="bg-panel border border-border rounded-lg p-3 hover:border-cyan-700 transition-colors"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="font-semibold text-slate-100">
                  <span className="text-cyan-400 font-mono mr-2">{sc.id}</span>
                  {sc.name}
                </div>
                <SeverityPill severity={sc.severity} />
              </div>
              <div className="text-xs font-mono text-slate-500 mt-1">{sc.mitre_id}</div>
              <div className="text-xs text-slate-400 mt-2 leading-relaxed">{sc.description}</div>

              <div className="flex items-center gap-2 mt-3">
                <div className="text-xs text-slate-400">Mode:</div>
                <button
                  onClick={() => setForId(sc.id, 0)}
                  className={`text-xs px-2 py-1 rounded border ${
                    s === 0
                      ? 'border-cyan-500 text-cyan-300 bg-cyan-500/10'
                      : 'border-border text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Noisy
                </button>
                <button
                  onClick={() => setForId(sc.id, 1)}
                  className={`text-xs px-2 py-1 rounded border ${
                    s === 1
                      ? 'border-cyan-500 text-cyan-300 bg-cyan-500/10'
                      : 'border-border text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Stealthy
                </button>
                <button
                  disabled={!!running}
                  onClick={() => onRun(sc.id, s)}
                  className="ml-auto text-xs px-3 py-1.5 rounded bg-cyan-500 text-ink font-semibold hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {isRunning ? 'Running…' : 'Run Simulation'}
                </button>
              </div>
            </div>
          )
        })}
      </div>

      <div className="px-4 py-3 border-t border-border bg-panel/50">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span>Detection coverage (this lab session)</span>
          <span className="font-mono">
            {coverage.fired} / {coverage.total}
          </span>
        </div>
        <div className="h-2 rounded bg-border overflow-hidden">
          <div
            className="h-full bg-cyan-500 transition-all"
            style={{ width: `${(coverage.fired / coverage.total) * 100}%` }}
          />
        </div>
      </div>
    </div>
  )
}
