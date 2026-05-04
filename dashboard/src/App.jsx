import { useEffect, useState, useCallback } from 'react'
import { api } from './lib/api'
import StatCard from './components/StatCard'
import AttackLauncher from './components/AttackLauncher'
import AlertFeed from './components/AlertFeed'
import TriageDrawer from './components/TriageDrawer'

export default function App() {
  const [scenarios, setScenarios] = useState([])
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [running, setRunning] = useState(null)
  const [loadError, setLoadError] = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [a, s] = await Promise.all([api.alerts(), api.stats()])
      setAlerts(a)
      setStats(s)
    } catch (e) {
      setLoadError(e.message)
    }
  }, [])

  useEffect(() => {
    api.scenarios().then(setScenarios).catch((e) => setLoadError(e.message))
    refresh()
  }, [refresh])

  useEffect(() => {
    if (!selectedId) {
      setSelectedAlert(null)
      return
    }
    api.alert(selectedId).then(setSelectedAlert).catch((e) => setLoadError(e.message))
  }, [selectedId])

  async function handleRun(scenario_id, stealth) {
    setRunning(scenario_id)
    try {
      const res = await api.simulate(scenario_id, stealth)
      await refresh()
      if (res.alerts && res.alerts.length > 0) {
        setSelectedId(res.alerts[0].id)
      }
    } catch (e) {
      setLoadError(e.message)
    } finally {
      setRunning(null)
    }
  }

  const coverage = {
    fired: stats?.techniques_covered?.length || 0,
    total: 5,
  }

  return (
    <div className="flex flex-col h-screen">
      <header className="flex items-center gap-4 px-6 py-3 border-b border-border bg-panel/40">
        <div>
          <div className="text-lg font-semibold tracking-tight">
            <span className="text-cyan-400">AD</span>Watchdog Lite
          </div>
          <div className="text-xs text-slate-500">
            Detection engineering workbench — synthetic AD logs, real detection logic, AI runbooks.
          </div>
        </div>
        <div className="ml-auto flex gap-2 flex-wrap">
          <StatCard
            label="Total Alerts"
            value={stats?.total_alerts ?? '–'}
            accent
          />
          <StatCard
            label="Critical"
            value={stats?.alerts_by_severity?.critical ?? '–'}
            hint={`${stats?.alerts_by_severity?.high ?? 0} high · ${stats?.alerts_by_severity?.medium ?? 0} med`}
          />
          <StatCard
            label="Techniques Fired"
            value={`${coverage.fired} / ${coverage.total}`}
            hint={`${stats?.detection_coverage_pct ?? 0}% coverage`}
          />
          <StatCard
            label="Runbooks Generated"
            value={stats?.runbooks_generated ?? 0}
          />
        </div>
      </header>

      {loadError && (
        <div className="px-6 py-2 bg-red-500/10 border-b border-red-500/30 text-xs text-red-300">
          {loadError}
        </div>
      )}

      <main className="flex-1 grid grid-cols-1 md:grid-cols-12 overflow-hidden">
        <div className="md:col-span-3 border-r border-border min-h-0">
          <AttackLauncher
            scenarios={scenarios}
            onRun={handleRun}
            running={running}
            coverage={coverage}
          />
        </div>
        <div className="md:col-span-4 border-r border-border min-h-0">
          <AlertFeed
            alerts={alerts}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        </div>
        <div className="md:col-span-5 min-h-0">
          <TriageDrawer
            alert={selectedAlert}
            onRunbookGenerated={refresh}
          />
        </div>
      </main>
    </div>
  )
}
