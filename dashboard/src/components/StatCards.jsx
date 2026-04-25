export default function StatCards({ stats }) {
  if (!stats) return <div className="panel"><div className="panel-label">Stats</div><p style={{color:'#4a6080'}}>Loading...</p></div>
  const cards = [
    { label:'Total Events', value: stats.total, color:'#c8d0dc' },
    { label:'Critical', value: stats.bySeverity?.CRITICAL??0, color:'#E24B4A' },
    { label:'High', value: stats.bySeverity?.HIGH??0, color:'#EF9F27' },
    { label:'Medium', value: stats.bySeverity?.MEDIUM??0, color:'#378ADD' },
  ]
  const types = Object.entries(stats.byType||{}).sort((a,b)=>b[1]-a[1])
  return (
    <div className="panel">
      <div className="panel-label">Statistics</div>
      <div className="stat-cards">
        {cards.map(c=>(
          <div key={c.label} className="stat-card">
            <div className="label">{c.label}</div>
            <div className="value" style={{color:c.color}}>{c.value}</div>
          </div>
        ))}
      </div>
      <div style={{marginTop:14}}>
        <div className="panel-label">By attack type</div>
        {types.map(([k,v])=>(
          <div key={k} style={{display:'flex',justifyContent:'space-between',fontSize:12,padding:'4px 0',borderBottom:'1px solid #12213a'}}>
            <span>{k}</span><span style={{color:'#378ADD'}}>{v}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
