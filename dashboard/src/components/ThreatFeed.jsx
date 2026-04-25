const BG = {CRITICAL:'#FCEBEB',HIGH:'#FAEEDA',MEDIUM:'#E6F1FB',LOW:'#EAF3DE'}
const FG = {CRITICAL:'#A32D2D',HIGH:'#633806',MEDIUM:'#0C447C',LOW:'#27500A'}
export default function ThreatFeed({ threats }) {
  return (
    <div className="panel">
      <div className="panel-label">Live threat feed</div>
      <div className="feed-list">
        {threats.slice(0,30).map((t,i)=>(
          <div key={i} className="feed-item">
            <span className="badge" style={{background:BG[t.severity]||'#eee',color:FG[t.severity]||'#333'}}>{t.severity}</span>
            <span>{t.attackType}</span>
            <span className="ip">{t.sourceIp}</span>
            <span className="country">{t.country}</span>
            <span className="ts">{t.timestamp?new Date(parseInt(t.timestamp)).toLocaleTimeString():'—'}</span>
          </div>
        ))}
      </div>
    </div>
  )
}