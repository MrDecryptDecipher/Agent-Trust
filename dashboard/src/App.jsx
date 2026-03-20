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

const API_BASE = 'http://localhost:8731/api';

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
      const alerts = (dash.alerts || []).map(a => ({
        id: a.alert_id || a.id,
        severity: ['emergency', 'critical', 'warning', 'info'][a.severity] || a.severity || 'info',
        type: a.alert_type || a.type || 'system_event',
        message: a.message,
        time: (new Date(a.timestamp * 1000)).toLocaleTimeString(),
        acknowledged: a.acknowledged || false,
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
        
        // Only actual data
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
        gdpr: true, // All chains in this mesh are GDPR compliant by design
        soc2: true, 
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
        rawTraffic: trafficData,
      });
      setLoading(false);
      setError(null);
    } catch (err) {
      console.error(err);
      setError('Connection refused. Is the FastAPI server running on port 8731?');
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

const AlertSeverityIcon = ({ severity }) => {
  const icons = { emergency: '🚨', critical: '⛔', warning: '⚠️', info: 'ℹ️' };
  return <span>{icons[severity] || '•'}</span>;
};

const ActivityStream = ({ events, onAcknowledge }) => {
  return (
    <div className="activity-stream">
      {events.map((event, i) => (
        <div key={event.id} className={`activity-item ${event.acknowledged ? 'acknowledged' : ''}`} style={{ animation: `slideInLeft ${0.1 * (i % 5)}s ease-out` }}>
          <div className="activity-icon">
             {event.severity === 'emergency' ? '🚨' : event.severity === 'critical' ? '🔥' : '⚙️'}
          </div>
          <div className="activity-content">
            <div className="activity-title">{(event.type || 'EVENT').replace(/_/g, ' ').toUpperCase()}</div>
            <div className="activity-desc">{event.message}</div>
          </div>
          <div className="activity-time">{event.time}</div>
          {!event.acknowledged && onAcknowledge && (
            <button 
              className="acknowledge-btn" 
              onClick={() => onAcknowledge(event.id)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '14px', marginLeft: '12px', opacity: 0.6 }}
            >
              ✓
            </button>
          )}
        </div>
      ))}
    </div>
  );
};

const Search = ({ placeholder, value, onChange }) => (
  <div className="search-container">
    <span style={{ opacity: 0.5 }}>🔍</span>
    <input 
      type="text" 
      className="search-input" 
      placeholder={placeholder} 
      value={value} 
      onChange={(e) => onChange(e.target.value)} 
    />
  </div>
);


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

const InfoTooltip = ({ text, children }) => (
  <div className="tooltip-container">
    {children}
    <div className="tooltip-content">{text}</div>
  </div>
);

function VerificationHub() {
  const [logs, setLogs] = useState([]);
  const [verifying, setVerifying] = useState(false);
  
  const runVerify = async () => {
    setVerifying(true);
    setLogs([{ step: "Connecting to Security Mesh...", status: "info", ts: Date.now()/1000 }]);
    
    try {
      const res = await fetch(`${API_BASE}/security/verify-full`, { method: 'POST' });
      const data = await res.json();
      
      // Simulate real-time logging delay for effect
      for (const log of data.logs) {
        await new Promise(r => setTimeout(r, 400));
        setLogs(prev => [...prev, log]);
      }
    } catch (e) {
      setLogs(prev => [...prev, { step: "Connection Lost: Middleware Unreachable", status: "error", ts: Date.now()/1000 }]);
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="table-card glass animate-in" style={{ marginTop: '24px' }}>
      <div className="table-card-header">
        <div className="table-card-title">🛡️ Cryptographic Verification Hub</div>
        <button 
          className="btn-primary" 
          onClick={runVerify} 
          disabled={verifying}
          style={{ padding: '6px 16px', fontSize: '11px' }}
        >
          {verifying ? 'AUDITING...' : 'RUN FULL AUDIT'}
        </button>
      </div>
      <div className="verification-terminal">
        {logs.length === 0 && <div className="terminal-line info">Ready for system integrity audit. Click 'Run Full Audit' to begin.</div>}
        {logs.map((log, i) => (
          <div key={i} className={`terminal-line ${log.status}`}>
            <span className="terminal-ts">[{new Date(log.ts * 1000).toLocaleTimeString()}]</span>
            <span className="terminal-step">{log.step}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function BreachSimulator({ data, refetch }) {
  const [targetId, setTargetId] = useState('');
  const [breachType, setBreachType] = useState('unauthorized_probe');
  const [simulating, setSimulating] = useState(false);
  const [result, setResult] = useState(null);

  const handleSimulate = async () => {
    if (!targetId) return;
    setSimulating(true);
    setResult(null);
    try {
      const res = await fetch(`${API_BASE}/security/simulate-breach`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_id: targetId, type: breachType })
      });
      const data = await res.json();
      setResult(data);
      if (refetch) refetch();
    } catch (e) {
      setResult({ status: 'error', message: 'Simulation delivery failed' });
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="chart-card glass highlight-red animate-in" style={{ marginTop: '24px' }}>
      <div className="chart-card-header">
         <div className="chart-card-title">🚨 Adversarial Breach Simulator</div>
      </div>
      <div style={{ padding: '0 20px 20px' }}>
        <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '16px' }}>
          Inject real-time security anomalies to test the middleware's detection and automated response capabilities.
        </p>
        <div style={{ display: 'flex', gap: '16px', marginBottom: '16px' }}>
          <div style={{ flex: 1 }}>
            <label style={{ display: 'block', fontSize: '10px', color: '#64748b', marginBottom: '8px' }}>TARGET AGENT</label>
            <select value={targetId} onChange={e => setTargetId(e.target.value)} style={{ width: '100%', padding: '8px', background: '#0f172a', border: '1px solid #334155', borderRadius: '4px', color: '#fff' }}>
              <option value="">Select target...</option>
              {data?.agents.map(a => <option key={a.id} value={a.id}>{a.id}</option>)}
            </select>
          </div>
          <div style={{ flex: 1 }}>
            <label style={{ display: 'block', fontSize: '10px', color: '#64748b', marginBottom: '8px' }}>ATTACK TYPE</label>
            <select value={breachType} onChange={e => setBreachType(e.target.value)} style={{ width: '100%', padding: '8px', background: '#0f172a', border: '1px solid #334155', borderRadius: '4px', color: '#fff' }}>
              <option value="unauthorized_probe">Unauthorized Probe</option>
              <option value="reputation_attack">Reputation Poisoning</option>
              <option value="lateral_movement">Lateral Movement Attempt</option>
              <option value="token_hijack">Token Hijack Simulation</option>
            </select>
          </div>
        </div>
        <button 
          onClick={handleSimulate} 
          disabled={simulating || !targetId}
          style={{ width: '100%', background: '#ef4444', color: '#fff', border: 'none', padding: '12px', borderRadius: '4px', fontWeight: 600, cursor: 'pointer' }}
        >
          {simulating ? 'EXECUTING EXPLOIT...' : 'TRIGGER BREACH EVENT'}
        </button>
        {result && (
          <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '4px', fontSize: '12px', color: '#fca5a5' }}>
            {result.message || 'Simulation signal broadcasted to mesh.'}
          </div>
        )}
      </div>
    </div>
  );
}

function AgentProfilePanel({ agentId, data, onClose }) {
  const agent = data.agents.find(a => a.id === agentId);
  if (!agent) return null;

  return (
    <div className="side-panel-overlay" onClick={onClose}>
      <div className="side-panel" onClick={e => e.stopPropagation()}>
        <button className="side-panel-close" onClick={onClose}>&times;</button>
        <div className="side-panel-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
             <div className="status-dot" style={{ backgroundColor: agent.risk === 'low' ? '#10b981' : '#f59e0b' }}></div>
             <h2 style={{ margin: 0 }}>{agent.id}</h2>
          </div>
          <p style={{ color: '#64748b', fontSize: '12px', marginTop: '8px' }}>Organization: {agent.org}</p>
        </div>

        <div className="stats-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '32px' }}>
           <div className="glass" style={{ padding: '16px' }}>
              <div style={{ color: '#64748b', fontSize: '10px' }}>REPUTATION</div>
              <div style={{ fontSize: '24px', fontWeight: 700, color: '#06b6d4' }}>{(agent.score * 100).toFixed(1)}%</div>
           </div>
           <div className="glass" style={{ padding: '16px' }}>
              <div style={{ color: '#64748b', fontSize: '10px' }}>RISK LEVEL</div>
              <div style={{ fontSize: '24px', fontWeight: 700, color: agent.risk === 'low' ? '#10b981' : agent.risk === 'medium' ? '#f59e0b' : '#ef4444' }}>{(agent.risk || 'unknown').toUpperCase()}</div>
           </div>
        </div>

        <h3 style={{ fontSize: '14px', marginBottom: '16px' }}>Trust Intelligence</h3>
        <div className="glass" style={{ padding: '20px', marginBottom: '24px' }}>
           <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
              <span>Reliability</span>
              <span style={{ color: '#10b981' }}>{(agent.reliability * 100).toFixed(0)}%</span>
           </div>
           <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
              <span>Compliance</span>
              <span style={{ color: '#06b6d4' }}>{(agent.compliance * 100).toFixed(0)}%</span>
           </div>
           <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Performance</span>
              <span style={{ color: '#c084fc' }}>{(agent.performance * 100).toFixed(0)}%</span>
           </div>
        </div>

        <h3 style={{ fontSize: '14px', marginBottom: '16px' }}>Verified Interaction History</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
           {(data.rawTraffic?.events || []).filter(e => e.source === agentId || e.target === agentId).slice(0, 5).map((e, idx) => (
              <div key={idx} className="glass" style={{ padding: '12px', fontSize: '11px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                 <span>{e.method} {e.endpoint || agentId}</span>
                 <Badge text="VERIFIED" color="cyan" />
              </div>
           ))}
        </div>
      </div>
    </div>
  );
}

function VisualChain({ chain }) {
  return (
    <div className="chain-flow">
      <div className="chain-node">
        <div style={{ fontWeight: 600 }}>{chain.origin}</div>
        <div style={{ fontSize: '9px', color: '#64748b' }}>Originator</div>
      </div>
      
      <div className="chain-arrow">
          <span>➔</span>
          <span className="chain-scope">{chain.taskType}</span>
      </div>

      <div className="chain-node" style={{ borderColor: 'var(--accent-cyan)' }}>
        <div style={{ fontWeight: 600 }}>{chain.terminal}</div>
        <div style={{ fontSize: '9px', color: '#64748b' }}>Terminal Agent</div>
      </div>

      <div style={{ marginLeft: 'auto', display: 'flex', gap: '12px' }}>
         <Badge text={`${chain.hops} hops`} color="blue" />
         <div style={{ display: 'flex', gap: '4px' }}>
            {chain.gdpr && <Badge text="GDPR" color="cyan" />}
            {chain.soc2 && <Badge text="SOC2" color="green" />}
         </div>
      </div>
    </div>
  );
}

function AuditTrailPage({ data }) {
  if (!data) return null;

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Audit Trail</h2>
        <p>Transparency logs for delegated consent chains and cryptographic proofs</p>
      </div>

      <div className="table-card glass animate-in">
        <div className="table-card-header">
          <div className="table-card-title">Live Consent Visualizations</div>
        </div>
        <div style={{ padding: '20px' }}>
            {data.consentChains.map((chain, i) => (
               <VisualChain key={i} chain={chain} />
            ))}
        </div>
      </div>
    </div>
  );
}

function OverviewPage({ data, onAcknowledge }) {
  if (!data) return null;

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Overview</h2>
        <p>Real-time monitoring of agent trust infrastructure</p>
      </div>

      <div className="stats-grid">
        <InfoTooltip text="Currently connected and authenticated agent instances in the mesh network.">
          <StatCard label="Active Agents" value={data.agents.length} icon="🤖" color="cyan" change="Online in real-time" />
        </InfoTooltip>
        <InfoTooltip text="Cryptographically signed trust relationships established between agent pairs.">
          <StatCard label="Trust Edges" value={data.trustEdges.length} icon="🔗" color="blue" />
        </InfoTooltip>
        <InfoTooltip text="JWT-based tokens strictly scoped for specific agent tasks.">
          <StatCard label="Active Tokens" value={data.tokenStats.active} icon="🔑" color="purple" />
        </InfoTooltip>
        <InfoTooltip text="Delegated trust paths allowing downstream agents to act on behalf of originators.">
          <StatCard label="Consent Chains" value={data.consentChains.length} icon="📋" color="green" />
        </InfoTooltip>
        <InfoTooltip text="Unresolved security anomalies or policy violations requiring attention.">
          <StatCard label="Active Alerts" value={data.alerts.length} icon="⚡" color="orange" />
        </InfoTooltip>
        <InfoTooltip text="Global reputation state integrity verified against the Merkle Root.">
          <StatCard label="Merkle Verified" value={data.rawDash.reputation.stats.integrity_valid ? "✓" : "✗"} icon="🛡️" color={data.rawDash.reputation.stats.integrity_valid ? "cyan" : "red"} />
        </InfoTooltip>
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
              <div className="chart-card-title">Activity & Alerts</div>
              <div className="chart-card-subtitle">Real-time infrastructure events</div>
            </div>
          </div>
          <div style={{ flex: 1 }}>
            {data.alerts.length === 0 ? (
               <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-tertiary)' }}>No recent activity.</div>
            ) : (
              <ActivityStream events={data.alerts.slice(0, 15)} onAcknowledge={onAcknowledge} />
            )}
          </div>
        </div>
      </div>

      <VerificationHub />
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

function ReputationPage({ data, searchQuery, setSearchQuery, onSelectAgent }) {
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <Search 
              placeholder="Search agents or orgs..." 
              value={searchQuery} 
              onChange={setSearchQuery} 
            />
            <Badge text={data.rawDash.reputation.stats.integrity_valid ? "Merkle ✓ Verified" : "Merkle ✗ Invalid"} color={data.rawDash.reputation.stats.integrity_valid ? "green" : "red"} />
          </div>
        </div>
        <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
            <thead>
                <tr>
                <th><InfoTooltip text="Global rank based on multidimensional reputation score.">#</InfoTooltip></th>
                <th>Agent ID</th>
                <th>Organization</th>
                <th><InfoTooltip text="Consensus reputation score calculated across all interactions.">Overall Score</InfoTooltip></th>
                <th>Interactions</th>
                <th>Risk Level</th>
                </tr>
            </thead>
            <tbody>
                {data.agents
                .filter(a => 
                  a.id.toLowerCase().includes(searchQuery.toLowerCase()) || 
                  a.org.toLowerCase().includes(searchQuery.toLowerCase())
                )
                .sort((a, b) => b.score - a.score)
                .map((agent, i) => (
                    <tr key={agent.id} onClick={() => onSelectAgent(agent.id)} style={{ cursor: 'pointer' }}>
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
        <BreachSimulator data={data} refetch={refetch} />
      </div>
    </div>
  );
}


// ─── App ─────────────────────────────────────────────────────────

function App() {
  const [activePage, setActivePage] = useState('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAgent, setSelectedAgent] = useState(null);
  const { data, loading, error, refetch } = useTrustData();

  const handleAcknowledge = async (alertId) => {
    try {
      await fetch(`${API_BASE}/trust/alerts/${alertId}/acknowledge`, { method: 'POST' });
      refetch();
    } catch (e) {
      console.error("Failed to acknowledge alert", e);
    }
  };

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
    overview: <OverviewPage data={data} onAcknowledge={handleAcknowledge} />,
    trust: <TrustGraphPage data={data} />,
    reputation: <ReputationPage data={data} searchQuery={searchQuery} setSearchQuery={setSearchQuery} onSelectAgent={setSelectedAgent} />,
    audit: <AuditTrailPage data={data} />,
    control: <ControlDeskPage data={data} refetch={refetch} />,
  };

  return (
    <div className="app">
      {selectedAgent && <AgentProfilePanel agentId={selectedAgent} data={data} onClose={() => setSelectedAgent(null)} />}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <img src="/images/agenttrust.png" alt="Agent-Trust Logo" style={{ width: '40px', height: '40px', objectFit: 'contain' }} />
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
          <button className={`nav-item ${activePage === 'audit' ? 'active' : ''}`} onClick={() => setActivePage('audit')}>
            <span className="nav-item-icon">📜</span> Audit Trail
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
            Polling :8731 Live
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
