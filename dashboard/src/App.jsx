import { useState, useEffect } from 'react'
import { getThreats, getStats } from './api'
import AttackMap from './components/AttackMap'
import ThreatFeed from './components/ThreatFeed'
import StatCards from './components/StatCards'
import TopAttackers from './components/TopAttackers'
import './styles/index.css'

export default function App() {
  const [threats, setThreats] = useState([])
  const [stats, setStats] = useState(null)

  useEffect(() => {
    const poll = async () => {
      const [t, s] = await Promise.all([getThreats(100), getStats()])
      setThreats(t)
      setStats(s)
    }
    poll()
    const id = setInterval(poll, 4000)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="app">
      <div className="header">
        <h1>⚡ THREAT INTELLIGENCE</h1>
        <div className="header-stats">
          TOTAL <span>{stats?.total ?? 0}</span>
          &nbsp;|&nbsp; CRITICAL <span style={{color:'#E24B4A'}}>{stats?.bySeverity?.CRITICAL ?? 0}</span>
          &nbsp;|&nbsp; HIGH <span style={{color:'#EF9F27'}}>{stats?.bySeverity?.HIGH ?? 0}</span>
        </div>
      </div>
      <div className="main-grid">
        <AttackMap threats={threats} />
        <StatCards stats={stats} />
      </div>
      <div className="bottom-grid">
        <ThreatFeed threats={threats} />
        <TopAttackers threats={threats} />
      </div>
    </div>
  )
}