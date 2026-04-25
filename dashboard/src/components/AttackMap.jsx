import { useEffect, useRef } from 'react'
const COLORS = { CRITICAL:'#E24B4A', HIGH:'#EF9F27', MEDIUM:'#378ADD', LOW:'#1D9E75' }
export default function AttackMap({ threats }) {
  const ref = useRef()
  useEffect(() => {
    const c = ref.current; if (!c || !threats.length) return
    const ctx = c.getContext('2d'), W = c.width, H = c.height
    ctx.clearRect(0,0,W,H)
    ctx.strokeStyle='rgba(55,138,221,0.12)'; ctx.lineWidth=0.5
    for(let i=0;i<=12;i++){ctx.beginPath();ctx.moveTo(i/12*W,0);ctx.lineTo(i/12*W,H);ctx.stroke()}
    for(let i=0;i<=6;i++){ctx.beginPath();ctx.moveTo(0,i/6*H);ctx.lineTo(W,i/6*H);ctx.stroke()}
    threats.slice(0,80).forEach(t=>{
      const lat=parseFloat(t.lat)||0, lon=parseFloat(t.lon)||0
      if(!lat&&!lon) return
      const x=(lon+180)/360*W, y=(90-lat)/180*H
      const color=COLORS[t.severity]||'#888', r=t.severity==='CRITICAL'?6:t.severity==='HIGH'?4:3
      ctx.beginPath();ctx.arc(x,y,r,0,Math.PI*2);ctx.fillStyle=color+'CC';ctx.fill()
      ctx.strokeStyle=color;ctx.lineWidth=1;ctx.stroke()
      if(t.severity==='CRITICAL'){ctx.beginPath();ctx.arc(x,y,r+5,0,Math.PI*2);ctx.strokeStyle=color+'44';ctx.lineWidth=1.5;ctx.stroke()}
    })
  },[threats])
  return (
    <div className="panel">
      <div className="panel-label">Live attack origins</div>
      <canvas ref={ref} width={640} height={300} style={{width:'100%',height:'auto'}}/>
      <div className="map-legend">
        {Object.entries(COLORS).map(([s,c])=>(
          <span key={s}><span style={{width:8,height:8,borderRadius:'50%',background:c,display:'inline-block'}}/>{s}</span>
        ))}
      </div>
    </div>
  )
}