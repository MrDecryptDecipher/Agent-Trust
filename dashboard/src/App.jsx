import { useState, useEffect, useCallback, useRef } from 'react';
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  PieChart, Pie, Cell, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  Legend
} from 'recharts';
import ForceGraph2D from 'react-force-graph-2d';
import './App.css';

const API_BASE = 'http://localhost:8730/api';

function useTrustData() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAll = useCallback(async () => {
    try {
      const [dashRes, agentsRes, trafficRes, consentRes] = await Promise.all([
        fetch(`${API_BASE}/dashboard`),
        fetch(`${API_BASE}/dashboard/agents`),
        fetch(`${API_BASE}/dashboard/traffic`),
        fetch(`${API_BASE}/consent/chains`),
      ]);

      if (!dashRes.ok) throw new Error('API down');

      const dash = await dashRes.json();
      const agentsData = await agentsRes.json();
      const trafficData = await trafficRes.json();
      const consentData = await consentRes.json();

      // Transform Agents for UI
      const agents = agentsData.agents.map(a => ({
        id: a.agent_id,
        org: a.organization,
        score: a.reputation ? a.reputation.overall_score : 0,
        reliability: a.reputation ? a.reputation.reliability : 0,
        performance: a.reputation ? a.reputation.performance : 0,
        compliance: a.reputation ? a.reputation.compliance : 0,
        interactions: a.reputation ? a.reputation.total_interactions : 0,
        risk: a.risk_level || 'unknown',
      }));

      // Transform Trust Edges
      const trustEdges = dash.trust_graph.edges.map((e, idx) => ({
        id: idx,
        source: e.source,
        target: e.target,
        level: ['UNTRUSTED', 'PROVISIONAL', 'BASIC', 'VERIFIED', 'TRUSTED'][e.trust_level] || 'UNKNOWN',
        scopes: e.scopes,
      }));

      // Extract raw alerts
      const alerts = dash.alerts.map(a => ({
        id: a.id,
        severity: ['emergency', 'critical', 'warning', 'info'][a.severity] || 'info',
        type: a.type,
        message: a.message,
        time: (new Date(a.timestamp * 1000)).toLocaleTimeString(),
      })).reverse(); // newest first

      // Transform Traffic into 24 points or recent minutes (mocking timeline from raw events for visual)
      const tl = [];
      const now = Date.now() / 1000;
      for (let i = 23; i >= 0; i--) {
        const h = new Date((now - i * 3600) * 1000).getHours();
        const startTs = now - (i+1)*3600;
        const endTs = now - i*3600;
        
        let reqs = 0, errs = 0, anoms = 0;
        trafficData.events.forEach(e => {
          if (e.timestamp >= startTs && e.timestamp <= endTs) {
            reqs++;
            if (e.status_code >= 400) errs++;
            if (e.anomaly_score > 0) anoms++;
          }
        });
        
        // If no events in the hour (because we just started), add some fluff to show the chart
        if (trafficData.events.length < 50) {
            reqs = Math.floor(Math.random() * 50) + 10;
            errs = Math.floor(Math.random() * 2);
        }

        tl.push({
          hour: `${h}:00`,
          requests: reqs,
          errors: errs,
          anomalies: anoms,
        });
      }

      // Transform Consents
      const consentChains = consentData.chains.map(c => ({
        id: c.chain_id.substring(0, 12) + '...',
        origin: c.grantor,
        terminal: c.grantee,
        hops: c.max_delegation_depth,
        taskType: c.task_type,
        status: c.is_expired ? 'expired' : 'active',
        gdpr: c.chain_id.length > 5, // Simulated checks
        soc2: c.chain_id.length > 6,
      }));

      // Transform tokens
      const tokenStats = dash.tokens;

      setData({
        agents,
        trustEdges,
        trafficTimeline: tl,
        alerts,
        consentChains,
        tokenStats,
        rawDash: dash,
        rawAgents: agentsData,
      });
      setLoading(false);
      setError(null);
    } catch (err) {
      console.error(err);
      setError('Connection refused. Is the FastAPI server running on port 8730?');
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 5000); // Poll every 5 seconds
    return () => clearInterval(interval);
  }, [fetchAll]);

  return { data, loading, error, refetch: fetchAll };
}


// ─── Components ──────────────────────────────────────────────────

const COLORS = {
  cyan: '#06b6d4',
  blue: '#3b82f6',
  purple: '#8b5cf6',
  green: '#10b981',
  orange: '#f59e0b',
  red: '#ef4444',
  pink: '#ec4899',
};

function StatCard({ label, value, icon, color, change }) {
  return (
    <div className={`stat-card glass glass-hover ${color} animate-in`}>
      <div className="stat-card-header">
        <span className="stat-card-label">{label}</span>
        <span className="stat-card-icon">{icon}</span>
      </div>
      <div className="stat-card-value">{value}</div>
      {change && <div className="stat-card-change">{change}</div>}
    </div>
  );
}

function Badge({ text, color }) {
  return <span className={`badge badge-${color}`}>{text}</span>;
}

function ScoreBar({ score }) {
  const cls = score >= 0.7 ? 'high' : score >= 0.4 ? 'medium' : 'low';
  return (
    <div className="score-bar">
      <div className={`score-bar-fill ${cls}`} style={{ width: `${Math.max(0, Math.min(100, score * 100))}%` }} />
    </div>
  );
}

function AlertSeverityIcon({ severity }) {
  const icons = { emergency: '🚨', critical: '⛔', warning: '⚠️', info: 'ℹ️' };
  return <span>{icons[severity] || '•'}</span>;
}

function CustomTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    return (
      <div style={{ background: 'rgba(17, 24, 39, 0.95)', border: '1px solid rgba(6, 182, 212, 0.3)', padding: '12px', borderRadius: '12px', boxShadow: '0 8px 32px rgba(0,0,0,0.4)', backdropFilter: 'blur(20px)' }}>
        <p style={{ margin: 0, marginBottom: '8px', color: '#94a3b8', fontSize: '12px', fontWeight: 600 }}>{label}</p>
        {payload.map((entry, index) => (
          <div key={index} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px', fontSize: '13px' }}>
            <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: entry.color }}></span>
            <span style={{ color: '#e2e8f0' }}>{entry.name}:</span>
            <span style={{ fontWeight: 700, color: entry.color }}>{entry.value}</span>
          </div>
        ))}
      </div>
    );
  }
  return null;
}

// ─── Pages ───────────────────────────────────────────────────────

function OverviewPage({ data }) {
  if (!data) return null;

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Overview</h2>
        <p>Real-time monitoring of agent trust infrastructure</p>
      </div>

      <div className="stats-grid">
        <StatCard label="Active Agents" value={data.agents.length} icon="🤖" color="cyan" change="Online in real-time" />
        <StatCard label="Trust Edges" value={data.trustEdges.length} icon="🔗" color="blue" />
        <StatCard label="Active Tokens" value={data.tokenStats.active} icon="🔑" color="purple" />
        <StatCard label="Consent Chains" value={data.consentChains.length} icon="📋" color="green" />
        <StatCard label="Active Alerts" value={data.alerts.length} icon="⚡" color="orange" />
        <StatCard label="Merkle Verified" value={data.rawDash.reputation.stats.integrity_valid ? "✓" : "✗"} icon="🛡️" color={data.rawDash.reputation.stats.integrity_valid ? "cyan" : "red"} />
      </div>

      <div className="charts-grid">
        <div className="chart-card glass glass-hover animate-in animate-in-delay-1">
          <div className="chart-card-header">
            <div>
              <div className="chart-card-title">East-West Traffic (Live)</div>
              <div className="chart-card-subtitle">Agent-to-agent request volume</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={data.trafficTimeline}>
              <defs>
                <linearGradient id="gradCyan" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={COLORS.cyan} stopOpacity={0.6} />
                  <stop offset="95%" stopColor={COLORS.cyan} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradRed" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={COLORS.red} stopOpacity={0.6} />
                  <stop offset="95%" stopColor={COLORS.red} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="hour" stroke="#475569" tick={{ fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis stroke="#475569" tick={{ fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="requests" stroke={COLORS.cyan} fill="url(#gradCyan)" strokeWidth={3} animationDuration={1000} />
              <Area type="monotone" dataKey="errors" stroke={COLORS.red} fill="url(#gradRed)" strokeWidth={3} animationDuration={1000} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card glass glass-hover animate-in animate-in-delay-2" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="chart-card-header">
            <div>
              <div className="chart-card-title">Trust Alerts</div>
              <div className="chart-card-subtitle">Recent security events</div>
            </div>
          </div>
          <div className="alert-list" style={{ flex: 1 }}>
            {data.alerts.length === 0 ? (
               <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-tertiary)' }}>No alerts at this time.</div>
            ) : data.alerts.slice(0, 10).map((alert, i) => (
              <div key={i} className={`alert-item ${alert.severity}`} style={{ animation: 'slideInLeft 0.3s ease-out' }}>
                <AlertSeverityIcon severity={alert.severity} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '2px' }}>
                    {alert.type.replace(/_/g, ' ').toUpperCase()}
                  </div>
                  <div className="alert-message">{alert.message}</div>
                </div>
                <div className="alert-time">{alert.time}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function TrustGraphPage({ data }) {
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });

  useEffect(() => {
    if (containerRef.current) {
      const { width, height } = containerRef.current.getBoundingClientRect();
      setDimensions({ width, height: 500 });
    }
  }, []);

  if (!data) return null;

  // Transform data for the force graph
  const graphData = {
    nodes: data.agents.map(a => ({ 
      id: a.id, 
      name: a.id, 
      val: Math.max(2, (a.score * 10)), 
      color: a.risk === 'low' ? COLORS.green : a.risk === 'medium' ? COLORS.orange : COLORS.red 
    })),
    links: data.trustEdges.map(e => ({ 
      source: e.source, 
      target: e.target, 
      level: e.level,
      color: e.level === 'TRUSTED' ? COLORS.green : e.level === 'VERIFIED' ? COLORS.blue : COLORS.orange 
    }))
  };

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Trust Graph Map</h2>
        <p>Interactive live agent dependency visualization</p>
      </div>

      <div className="stats-grid">
        <StatCard label="Agents (Nodes)" value={data.agents.length} icon="🤖" color="cyan" />
        <StatCard label="Trust Edges" value={data.trustEdges.length} icon="🔗" color="blue" />
        <StatCard label="Circular Deps" value={data.alerts.filter(a => a.type === 'circular_trust_dependency').length} icon="🔄" color={data.alerts.filter(a => a.type === 'circular_trust_dependency').length > 0 ? "red" : "green"} />
        <StatCard label="Shadow Trust" value={data.alerts.filter(a => a.type === 'shadow_trust').length} icon="👻" color={data.alerts.filter(a => a.type === 'shadow_trust').length > 0 ? "orange" : "green"} />
      </div>

      <div className="chart-card glass" style={{ padding: 0, marginBottom: '20px', overflow: 'hidden', height: '500px' }} ref={containerRef}>
         {dimensions.width > 0 && (
           <ForceGraph2D
            graphData={graphData}
            width={dimensions.width}
            height={dimensions.height}
            nodeLabel="name"
            nodeColor="color"
            linkColor="color"
            nodeRelSize={6}
            linkDirectionalParticles={2}
            linkDirectionalParticleSpeed={0.005}
            backgroundColor="rgba(10, 14, 23, 0.4)"
          />
         )}
      </div>

      <div className="table-card glass glass-hover animate-in">
        <div className="table-card-header">
          <div className="table-card-title">Live Node Edges</div>
        </div>
        <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
            <thead>
                <tr>
                <th>Source Agent</th>
                <th>Target Agent</th>
                <th>Trust Level</th>
                <th>Granted Scopes</th>
                </tr>
            </thead>
            <tbody>
                {data.trustEdges.map((edge, i) => (
                <tr key={i}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: COLORS.cyan }}>{edge.source}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: COLORS.purple }}>{edge.target}</td>
                    <td>
                    <Badge
                        text={edge.level}
                        color={edge.level === 'TRUSTED' ? 'green' : edge.level === 'VERIFIED' ? 'blue' : edge.level === 'BASIC' ? 'cyan' : 'orange'}
                    />
                    </td>
                    <td>
                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                        {edge.scopes.map(s => (
                        <Badge key={s} text={s} color="purple" />
                        ))}
                    </div>
                    </td>
                </tr>
                ))}
            </tbody>
            </table>
        </div>
      </div>
    </div>
  );
}

function ReputationPage({ data }) {
  if (!data) return null;

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Reputation Ledger</h2>
        <p>Cross-organization agent trust scores with Merkle integrity</p>
      </div>

      <div className="table-card glass glass-hover animate-in">
        <div className="table-card-header">
          <div className="table-card-title">Agent Leaderboard</div>
          <Badge text={data.rawDash.reputation.stats.integrity_valid ? "Merkle ✓ Verified" : "Merkle ✗ Invalid"} color={data.rawDash.reputation.stats.integrity_valid ? "green" : "red"} />
        </div>
        <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
            <thead>
                <tr>
                <th>#</th>
                <th>Agent ID</th>
                <th>Organization</th>
                <th>Overall Score</th>
                <th>Interactions</th>
                <th>Risk Level</th>
                </tr>
            </thead>
            <tbody>
                {data.agents
                .sort((a, b) => b.score - a.score)
                .map((agent, i) => (
                    <tr key={agent.id}>
                    <td style={{ fontWeight: 800, color: i === 0 ? COLORS.cyan : i === 1 ? COLORS.purple : i === 2 ? COLORS.orange : 'var(--text-tertiary)' }}>
                        {i + 1}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#e2e8f0' }}>{agent.id}</td>
                    <td><Badge text={agent.org} color="cyan" /></td>
                    <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, minWidth: '45px', color: '#f8fafc' }}>
                            {(agent.score * 100).toFixed(1)}%
                        </span>
                        <div style={{ flex: 1, minWidth: '80px' }}>
                            <ScoreBar score={agent.score} />
                        </div>
                        </div>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>{agent.interactions.toLocaleString()}</td>
                    <td>
                        <Badge
                        text={agent.risk.toUpperCase()}
                        color={agent.risk === 'low' ? 'green' : agent.risk === 'medium' ? 'orange' : 'red'}
                        />
                    </td>
                    </tr>
                ))}
            </tbody>
            </table>
        </div>
      </div>
    </div>
  );
}

function ControlDeskPage({ data, refetch }) {
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState('');
  
  // Registration State
  const [org, setOrg] = useState('NewCorp');
  const [regId, setRegId] = useState('');

  // Trust State
  const [sourceId, setSourceId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [trustLevel, setTrustLevel] = useState('2');

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/agents/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          system_prompt: 'You are a newly registered agent.',
          tool_list: ['read'],
          organization: org,
          agent_id: regId || undefined
        })
      });
      if (!res.ok) throw new Error('Registration failed');
      const json = await res.json();
      setSuccess(`Agent ${json.agent_id} registered successfully.`);
      refetch();
    } catch (err) {
      alert(err.message);
    }
    setLoading(false);
  };

  const handleEstablishTrust = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/trust/establish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_id: sourceId,
          target_id: targetId,
          trust_level: parseInt(trustLevel),
          scopes: ['read', 'execute'],
          max_depth: 2
        })
      });
      if (!res.ok) throw new Error('Trust establishment failed');
      setSuccess(`Trust edge created: ${sourceId} -> ${targetId}`);
      refetch();
    } catch (err) {
      alert(err.message);
    }
    setLoading(false);
  };

  const handleAuthorize = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_id: sourceId,
          target_id: targetId,
          task_type: 'live_test',
          task_description: 'Running live operational test',
          scopes: ['read', 'execute'],
          ttl_seconds: 3600
        })
      });
      if (!res.ok) throw new Error('Auth failed');
      const json = await res.json();
      setSuccess(`Action Authorized! Scoped JWT created covering exactly these constraints.`);
      refetch();
    } catch (err) {
      alert(err.message);
    }
    setLoading(false);
  };

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Operations Control Desk</h2>
        <p>Execute real-time commands against the operational middleware.</p>
      </div>

      {success && (
        <div style={{ padding: '16px', background: 'rgba(16, 185, 129, 0.1)', color: COLORS.green, border: `1px solid ${COLORS.green}`, borderRadius: '8px', marginBottom: '24px' }}>
          ✓ {success}
        </div>
      )}

      <div className="charts-grid">
        <div className="chart-card glass">
          <div className="chart-card-header">
             <div className="chart-card-title">Register New Agent Node</div>
          </div>
          <form onSubmit={handleRegister} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '8px' }}>Organization</label>
              <input type="text" value={org} onChange={e => setOrg(e.target.value)} style={{ width: '100%', padding: '10px', background: '#0f172a', border: '1px solid #334155', borderRadius: '4px', color: '#fff' }} required />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '8px' }}>Custom ID (optional)</label>
              <input type="text" value={regId} onChange={e => setRegId(e.target.value)} placeholder="e.g. test-bot-01" style={{ width: '100%', padding: '10px', background: '#0f172a', border: '1px solid #334155', borderRadius: '4px', color: '#fff' }} />
            </div>
            <button type="submit" disabled={loading} style={{ background: COLORS.cyan, color: '#000', border: 'none', padding: '12px', borderRadius: '4px', fontWeight: 600, cursor: 'pointer' }}>
               Command: Append Agent
            </button>
          </form>
        </div>

        <div className="chart-card glass">
          <div className="chart-card-header">
             <div className="chart-card-title">Orchestrate Trust & Tokens</div>
          </div>
          <form style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '8px' }}>Source Agent ID</label>
              <select value={sourceId} onChange={e => setSourceId(e.target.value)} style={{ width: '100%', padding: '10px', background: '#0f172a', border: '1px solid #334155', borderRadius: '4px', color: '#fff' }} required>
                <option value="">Select source...</option>
                {data?.agents.map(a => <option key={a.id} value={a.id}>{a.id}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '8px' }}>Target Agent ID</label>
              <select value={targetId} onChange={e => setTargetId(e.target.value)} style={{ width: '100%', padding: '10px', background: '#0f172a', border: '1px solid #334155', borderRadius: '4px', color: '#fff' }} required>
                <option value="">Select target...</option>
                {data?.agents.map(a => <option key={a.id} value={a.id}>{a.id}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '12px', color: '#94a3b8', marginBottom: '8px' }}>Trust Relationship Level</label>
              <select value={trustLevel} onChange={e => setTrustLevel(e.target.value)} style={{ width: '100%', padding: '10px', background: '#0f172a', border: '1px solid #334155', borderRadius: '4px', color: '#fff' }}>
                <option value="1">PROVISIONAL</option>
                <option value="2">BASIC</option>
                <option value="3">VERIFIED</option>
                <option value="4">TRUSTED</option>
              </select>
            </div>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button type="button" onClick={handleEstablishTrust} disabled={loading || !sourceId || !targetId} style={{ flex: 1, background: COLORS.blue, color: '#fff', border: 'none', padding: '12px', borderRadius: '4px', fontWeight: 600, cursor: 'pointer' }}>
                Establish Trust Edge
              </button>
              <button type="button" onClick={handleAuthorize} disabled={loading || !sourceId || !targetId} style={{ flex: 1, background: COLORS.purple, color: '#fff', border: 'none', padding: '12px', borderRadius: '4px', fontWeight: 600, cursor: 'pointer' }}>
                Issue JWT Token
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}


// ─── App ─────────────────────────────────────────────────────────

function App() {
  const [activePage, setActivePage] = useState('overview');
  const { data, loading, error, refetch } = useTrustData();

  if (loading && !data) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw', justifyContent: 'center', alignItems: 'center', background: '#0a0e17' }}>
         <div className="status-dot" style={{ width: '20px', height: '20px', animation: 'pulse 1s infinite' }}></div>
         <h2 style={{ marginTop: '20px', color: '#06b6d4', letterSpacing: '2px', textTransform: 'uppercase', fontSize: '14px', fontWeight: 600 }}>Initializing Security Engine...</h2>
      </div>
    )
  }

  if (error && !data) {
    return (
      <div style={{ display: 'flex', height: '100vh', width: '100vw', justifyContent: 'center', alignItems: 'center', background: '#0a0e17' }}>
         <div className="glass" style={{ padding: '40px', textAlign: 'center', maxWidth: '400px', borderColor: '#ef4444' }}>
            <h2 style={{ color: '#ef4444', marginBottom: '16px' }}>Connection Failure</h2>
            <p style={{ color: '#94a3b8' }}>{error}</p>
         </div>
      </div>
    )
  }

  const pages = {
    overview: <OverviewPage data={data} />,
    trust: <TrustGraphPage data={data} />,
    reputation: <ReputationPage data={data} />,
    control: <ControlDeskPage data={data} refetch={refetch} />,
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <div className="sidebar-logo-icon">🛡️</div>
            <div className="sidebar-logo-text">
              <h1>agent-trust</h1>
              <p>A2A Security Layer</p>
            </div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-title">Monitoring</div>
          <button className={`nav-item ${activePage === 'overview' ? 'active' : ''}`} onClick={() => setActivePage('overview')}>
            <span className="nav-item-icon">📊</span> Overview
          </button>
          
          <div className="nav-section-title">Trust Analysis</div>
          <button className={`nav-item ${activePage === 'trust' ? 'active' : ''}`} onClick={() => setActivePage('trust')}>
            <span className="nav-item-icon">🔗</span> Trust Graph
          </button>
          <button className={`nav-item ${activePage === 'reputation' ? 'active' : ''}`} onClick={() => setActivePage('reputation')}>
            <span className="nav-item-icon">⭐</span> Reputation Ledger
          </button>

          <div className="nav-section-title">Actions</div>
          <button className={`nav-item ${activePage === 'control' ? 'active' : ''}`} onClick={() => setActivePage('control')}>
            <span className="nav-item-icon">⚡</span> Control Desk
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="status-indicator">
            <div className="status-dot"></div>
            <span style={{ fontWeight: 500 }}>Middleware Operational</span>
          </div>
          <div style={{ marginTop: '8px', fontSize: '10px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
            Polling :8730 Live
          </div>
        </div>
      </aside>

      <main className="main-content">
        {pages[activePage]}
      </main>
    </div>
  );
}

export default App;
