export default function TopAttackers({ threats }) {
  const counts = {}
  threats.forEach(t=>{ counts[t.sourceIp]=(counts[t.sourceIp]||0)+1 })
  const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,10)
  const max = sorted[0]?.[1]||1
  return (
    <div className="panel">
      <div className="panel-label">Top attackers</div>
      <div className="attackers-list">
        {sorted.map(([ip,count])=>(
          <div key={ip} className="attacker-row">
            <span className="ip">{ip}</span>
            <div className="bar-wrap"><div className="bar" style={{width:`${count/max*100}%`}}/></div>
            <span style={{color:'#EF9F27',fontWeight:700}}>{count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}