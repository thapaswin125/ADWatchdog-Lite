export default function StatCard({ label, value, hint, accent = false }) {
  return (
    <div className="bg-panel border border-border rounded-lg px-4 py-3 flex-1 min-w-[160px]">
      <div className="text-xs uppercase tracking-wider text-slate-400">{label}</div>
      <div className={`text-2xl font-semibold mt-1 ${accent ? 'text-cyan-300' : 'text-slate-100'}`}>
        {value}
      </div>
      {hint && <div className="text-xs text-slate-500 mt-1">{hint}</div>}
    </div>
  )
}
