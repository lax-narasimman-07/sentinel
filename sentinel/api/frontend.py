def get_dashboard_html() -> str:
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL Security Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            sentinel: { 50:'#f0f9ff', 100:'#e0f2fe', 200:'#bae6fd', 300:'#7dd3fc', 400:'#38bdf8', 500:'#0ea5e9', 600:'#0284c7', 700:'#0369a1', 800:'#075985', 900:'#0c4a6e' }
          }
        }
      }
    }
    </script>
    <style>
      body { margin:0; background:#0a0a0f; color:#e5e7eb; font-family:'Inter','Segoe UI',system-ui,sans-serif; }
      ::-webkit-scrollbar { width:6px; height:6px; }
      ::-webkit-scrollbar-track { background:#111827; }
      ::-webkit-scrollbar-thumb { background:#374151; border-radius:3px; }
      ::-webkit-scrollbar-thumb:hover { background:#4b5563; }
      @keyframes fadeIn { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
      .fade-in { animation: fadeIn 0.15s ease-out; }
      @keyframes pulse-dot { 0%,100%{opacity:1} 50%{opacity:0.3} }
      .pulse-dot { animation: pulse-dot 2s infinite; }
      @keyframes spin { to{transform:rotate(360deg)} }
      .animate-spin { animation: spin 1s linear infinite; }
      pre, code, .mono { font-family:'JetBrains Mono','Fira Code','Cascadia Code',monospace; font-size:12px; }
      input:focus, select:focus, textarea:focus { outline:none; border-color:#3b82f6; }
    </style>
</head>
<body>
    <div id="root"></div>
    <script type="text/babel">
    const { useState, useEffect, useCallback, useRef, useMemo, createContext, useContext } = React;

    const api = {
      async get(path) { const r = await fetch(path); if (!r.ok) { const t = await r.text().catch(() => r.statusText); throw new Error(t || `HTTP ${r.status}`); } return r.json(); },
      async post(path, body) { const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body !== undefined ? JSON.stringify(body) : undefined }); if (!r.ok) { const t = await r.text().catch(() => r.statusText); throw new Error(t || `HTTP ${r.status}`); } return r.json(); },
      async del(path) { const r = await fetch(path, { method: 'DELETE' }); if (!r.ok) { const t = await r.text().catch(() => r.statusText); throw new Error(t || `HTTP ${r.status}`); } return r.json(); },
    };

    const ToastCtx = createContext(null);
    function ToastProvider({ children }) {
      const [toasts, setToasts] = useState([]);
      const add = useCallback((msg, type = 'info') => {
        const id = Date.now() + Math.random();
        setToasts(p => [...p.slice(-4), { id, msg, type }]);
        setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), 4000);
      }, []);
      return React.createElement(ToastCtx.Provider, { value: { add } }, children,
        React.createElement('div', { className: 'fixed bottom-4 right-4 z-50 flex flex-col gap-2' },
          toasts.map(t => React.createElement('div', { key: t.id, className: `px-4 py-2.5 rounded-lg text-sm font-medium shadow-lg border transition-all ${
            t.type === 'error' ? 'bg-red-900/90 text-red-200 border-red-700/50' :
            t.type === 'success' ? 'bg-green-900/90 text-green-200 border-green-700/50' :
            t.type === 'warn' ? 'bg-yellow-900/90 text-yellow-200 border-yellow-700/50' :
            'bg-gray-800/90 text-gray-200 border-gray-600/50' }` }, t.msg))));
    }
    const useToast = () => useContext(ToastCtx);

    const Badge = ({ children, color = 'gray' }) => {
      const c = { red:'bg-red-900/40 text-red-300 border-red-700/40', orange:'bg-orange-900/40 text-orange-300 border-orange-700/40',
        yellow:'bg-yellow-900/40 text-yellow-300 border-yellow-700/40', green:'bg-green-900/40 text-green-300 border-green-700/40',
        blue:'bg-blue-900/40 text-blue-300 border-blue-700/40', purple:'bg-purple-900/40 text-purple-300 border-purple-700/40',
        gray:'bg-gray-800/60 text-gray-300 border-gray-600/40', cyan:'bg-cyan-900/40 text-cyan-300 border-cyan-700/40' };
      return React.createElement('span', { className: `inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${c[color] || c.gray}` }, children);
    };
    const SeverityBadge = ({ severity }) => {
      const m = { critical:'red', high:'orange', medium:'yellow', low:'blue', informational:'gray' };
      return React.createElement(Badge, { color: m[severity] || 'gray' }, (severity || 'N/A').toUpperCase());
    };
    const StatusBadge = ({ status }) => {
      const m = { active:'green', completed:'blue', running:'green', failed:'red', queued:'yellow', cancelled:'gray', pending:'yellow', validated:'green', rejected:'red', candidate:'purple', solved:'green', open:'blue', closed:'gray' };
      return React.createElement(Badge, { color: m[status] || 'gray' }, status);
    };
    const Btn = ({ onClick, children, color = 'blue', disabled = false, small = false, className = '' }) => {
      const c = { blue:'bg-blue-600 hover:bg-blue-500 text-white', green:'bg-green-600 hover:bg-green-500 text-white',
        red:'bg-red-600 hover:bg-red-500 text-white', yellow:'bg-yellow-600 hover:bg-yellow-500 text-black',
        gray:'bg-gray-700 hover:bg-gray-600 text-gray-200', purple:'bg-purple-600 hover:bg-purple-500 text-white',
        cyan:'bg-cyan-600 hover:bg-cyan-500 text-white', orange:'bg-orange-600 hover:bg-orange-500 text-white' };
      return React.createElement('button', { onClick, disabled,
        className: `${small ? 'px-2.5 py-1 text-xs' : 'px-4 py-2 text-sm'} rounded-lg font-medium transition-all ${c[color] || c.blue} ${disabled ? 'opacity-40 cursor-not-allowed' : 'cursor-pointer'} ${className}` }, children);
    };
    const Card = ({ children, className = '', onClick }) =>
      React.createElement('div', { onClick, className: `bg-[#1a1f2e] border border-gray-700/40 rounded-xl ${className}` }, children);
    const Loading = ({ text = 'Loading...' }) =>
      React.createElement('div', { className: 'flex items-center gap-2 text-gray-400 text-sm py-4' },
        React.createElement('div', { className: 'w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin' }), text);
    const Empty = ({ icon = '\u{1F4ED}', text = 'Nothing here yet' }) =>
      React.createElement('div', { className: 'flex flex-col items-center justify-center py-16 text-gray-500' },
        React.createElement('span', { className: 'text-4xl mb-3' }, icon),
        React.createElement('span', { className: 'text-sm' }, text));
    const Modal = ({ open, onClose, title, children, wide }) => {
      if (!open) return null;
      return React.createElement('div', { className: 'fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm', onClick: onClose },
        React.createElement('div', { className: `bg-[#1a1f2e] border border-gray-700/60 rounded-2xl p-6 ${wide ? 'max-w-2xl' : 'max-w-lg'} w-full max-h-[85vh] overflow-y-auto mx-4`, onClick: e => e.stopPropagation() },
          React.createElement('div', { className: 'flex items-center justify-between mb-5' },
            React.createElement('h3', { className: 'text-lg font-bold text-white' }, title),
            React.createElement('button', { onClick: onClose, className: 'text-gray-400 hover:text-white text-2xl leading-none' }, '\u00D7')),
          children));
    };
    const Input = ({ label, value, onChange, placeholder, type = 'text', className = '' }) =>
      React.createElement('div', { className: `mb-3 ${className}` },
        label && React.createElement('label', { className: 'block text-xs font-medium text-gray-400 mb-1.5' }, label),
        React.createElement('input', { type, value: value || '', onChange: e => onChange(e.target.value), placeholder,
          className: 'w-full bg-gray-800/80 border border-gray-600/60 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500' }));
    const Select = ({ label, value, onChange, options, className = '' }) =>
      React.createElement('div', { className: `mb-3 ${className}` },
        label && React.createElement('label', { className: 'block text-xs font-medium text-gray-400 mb-1.5' }, label),
        React.createElement('select', { value: value || '', onChange: e => onChange(e.target.value),
          className: 'w-full bg-gray-800/80 border border-gray-600/60 rounded-lg px-3 py-2 text-sm text-white focus:border-blue-500' },
          options.map(o => React.createElement('option', { key: typeof o === 'string' ? o : o.value, value: typeof o === 'string' ? o : o.value },
            typeof o === 'string' ? o : o.label))));
    const TextArea = ({ label, value, onChange, placeholder, rows = 4, className = '' }) =>
      React.createElement('div', { className: `mb-3 ${className}` },
        label && React.createElement('label', { className: 'block text-xs font-medium text-gray-400 mb-1.5' }, label),
        React.createElement('textarea', { value: value || '', onChange: e => onChange(e.target.value), placeholder, rows,
          className: 'w-full bg-gray-800/80 border border-gray-600/60 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 resize-y' }));
    const Tabs = ({ tabs, active, onChange }) =>
      React.createElement('div', { className: 'flex gap-1 mb-4 flex-wrap' },
        tabs.map(t => React.createElement('button', { key: t.id, onClick: () => onChange(t.id),
          className: `px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${active === t.id ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/50'}` }, t.label)));
    const PageHeader = ({ title, subtitle, children }) =>
      React.createElement('div', { className: 'flex items-center justify-between mb-6' },
        React.createElement('div', null,
          React.createElement('h2', { className: 'text-2xl font-bold text-white' }, title),
          subtitle && React.createElement('p', { className: 'text-sm text-gray-400 mt-1' }, subtitle)),
        React.createElement('div', { className: 'flex gap-2' }, children));

    function ScopeCheckInput({ engagementId, label, value, onChange, placeholder }) {
      const [scopeStatus, setScopeStatus] = useState(null);
      const [checking, setChecking] = useState(false);
      useEffect(() => {
        if (!engagementId || !value || value.length < 3) { setScopeStatus(null); return; }
        const t = setTimeout(() => {
          setChecking(true);
          api.post(`/api/scope/${engagementId}/check`, { target: value })
            .then(r => setScopeStatus(r.in_scope !== undefined ? r.in_scope : r.allowed))
            .catch(() => setScopeStatus(null))
            .finally(() => setChecking(false));
        }, 600);
        return () => clearTimeout(t);
      }, [engagementId, value]);
      return React.createElement('div', { className: 'mb-3' },
        React.createElement('div', { className: 'flex items-center gap-2' },
          React.createElement('div', { className: 'flex-1' }, React.createElement(Input, { label, value, onChange, placeholder })),
          React.createElement('div', { className: 'pt-5' },
            checking
              ? React.createElement('div', { className: 'w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin' })
              : scopeStatus !== null && React.createElement(Badge, { color: scopeStatus ? 'green' : 'red' }, scopeStatus ? 'IN SCOPE' : 'OUT OF SCOPE'))));
    }

    const NAV_GROUPS = [
      { id: 'bugbounty', label: 'Bug Bounty', icon: '\u{1F3AF}', pages: [
        { id: 'bb-dashboard', label: 'Dashboard' }, { id: 'engagements', label: 'Engagements' },
        { id: 'scope', label: 'Scope Manager' }, { id: 'recon', label: 'Recon' },
        { id: 'web-security', label: 'Web Security' }, { id: 'api-security', label: 'API Security' },
        { id: 'auth-testing', label: 'Auth Testing' }]},
      { id: 'ctf', label: 'CTF', icon: '\u{1F9E9}', pages: [
        { id: 'ctf-challenges', label: 'Challenges' }, { id: 'ctf-workspace', label: 'Workspace' },
        { id: 'crypto-tools', label: 'Crypto Tools' }, { id: 'forensics-tools', label: 'Forensics' }]},
      { id: 'tools', label: 'Tools', icon: '\u{1F527}', pages: [
        { id: 'tool-manager', label: 'Tool Manager' }, { id: 'workflow-builder', label: 'Workflows' }]},
      { id: 'workspaces', label: 'Workspaces', icon: '\u{1F310}', pages: [
        { id: 'http-client', label: 'HTTP Client' }, { id: 'browser-ws', label: 'Browser' },
        { id: 'attack-surface', label: 'Attack Surface' }]},
      { id: 'analysis', label: 'Analysis', icon: '\u{1F50D}', pages: [
        { id: 'hypotheses', label: 'Hypotheses' }, { id: 'findings', label: 'Findings' },
        { id: 'evidence', label: 'Evidence Vault' }, { id: 'reports', label: 'Reports' }]},
      { id: 'jobs', label: 'Jobs', icon: '\u26A1', pages: [
        { id: 'job-center', label: 'Job Center' }]},
      { id: 'system', label: 'System', icon: '\u2699', pages: [
        { id: 'settings', label: 'Settings' }]}
    ];

    const WSContext = createContext(null);
    function WSProvider({ children }) {
      const [connected, setConnected] = useState(false);
      const wsRef = useRef(null);
      useEffect(() => {
        const connect = () => {
          try {
            const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(`${proto}//${location.host}/ws`);
            ws.onopen = () => setConnected(true);
            ws.onclose = () => { setConnected(false); setTimeout(connect, 3000); };
            wsRef.current = ws;
          } catch(e) { setTimeout(connect, 3000); }
        };
        connect();
        return () => { if (wsRef.current) wsRef.current.close(); };
      }, []);
      return React.createElement(WSContext.Provider, { value: { connected } }, children);
    }

    function DashboardHome({ setPage }) {
      const [data, setData] = useState(null);
      const [loading, setLoading] = useState(true);
      useEffect(() => {
        Promise.all([
          api.get('/api/system').catch(() => ({})),
          api.get('/api/engagements').catch(() => ({ engagements: [] })),
          api.get('/api/findings').catch(() => ({ findings: [] })),
          api.get('/api/jobs').catch(() => ({ jobs: [] })),
          api.get('/api/tools-health').catch(() => api.get('/api/tools').catch(() => ({ tools: {} }))),
        ]).then(([sys, eng, find, jobs, tools]) => {
          setData({ system: sys, engagements: eng.engagements || [], findings: find.findings || [], jobs: jobs.jobs || [], tools: tools.tools || tools });
          setLoading(false);
        }).catch(() => setLoading(false));
      }, []);
      if (loading) return React.createElement(Loading);
      if (!data) return React.createElement(Empty, { text: 'Failed to load dashboard' });
      const toolCount = data.tools ? (Array.isArray(data.tools) ? data.tools.length : Object.keys(data.tools).length) : 0;
      const activeFindings = data.findings.filter(f => f.validation_status !== 'rejected').length;
      const stats = [
        { label: 'Engagements', value: data.engagements.length, color: 'blue', icon: '\u{1F3AF}', page: 'engagements' },
        { label: 'Active Findings', value: activeFindings, color: 'red', icon: '\u{1F50D}', page: 'findings' },
        { label: 'Tools', value: toolCount, color: 'green', icon: '\u{1F527}', page: 'tool-manager' },
        { label: 'Jobs Run', value: data.jobs.length, color: 'yellow', icon: '\u26A1', page: 'job-center' },
      ];
      const quickActions = [
        { label: 'New Engagement', page: 'engagements' }, { label: 'Recon Scan', page: 'recon' },
        { label: 'HTTP Client', page: 'http-client' }, { label: 'Web Security', page: 'web-security' },
        { label: 'CTF Challenges', page: 'ctf-challenges' }, { label: 'Reports', page: 'reports' },
      ];
      const recentActivity = [
        ...data.engagements.slice(-3).map(e => ({ text: `Engagement: ${e.name}`, status: e.status, time: e.created_at })),
        ...data.findings.slice(-3).map(f => ({ text: `Finding: ${f.title}`, severity: f.severity, time: f.created_at })),
        ...data.jobs.slice(-3).map(j => ({ text: `Job: ${j.tool_name || j.workflow || 'unknown'}`, status: j.status, time: j.started_at })),
      ].sort((a, b) => (b.time || '').localeCompare(a.time || '')).slice(0, 8);
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Security Dashboard', subtitle: 'SENTINEL Security Platform v0.1.0' }),
        React.createElement('div', { className: 'grid grid-cols-2 md:grid-cols-4 gap-4 mb-8' },
          stats.map(s => React.createElement(Card, { key: s.label, className: 'p-5 cursor-pointer hover:border-gray-600/60 transition-all', onClick: () => setPage(s.page) },
            React.createElement('div', { className: 'flex items-center justify-between mb-3' },
              React.createElement('span', { className: 'text-gray-400 text-xs font-medium uppercase tracking-wide' }, s.label),
              React.createElement('span', { className: 'text-xl' }, s.icon)),
            React.createElement('div', { className: 'text-3xl font-bold text-white' }, s.value)))),
        React.createElement('h3', { className: 'text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3' }, 'Quick Actions'),
        React.createElement('div', { className: 'grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-8' },
          quickActions.map(a => React.createElement('button', { key: a.label, onClick: () => setPage(a.page),
            className: 'bg-gray-800/40 border border-gray-700/30 rounded-xl p-4 text-center hover:border-blue-500/40 hover:bg-gray-800/60 transition-all cursor-pointer' },
            React.createElement('div', { className: 'text-sm text-gray-300 font-medium' }, a.label)))),
        React.createElement('div', { className: 'grid grid-cols-1 lg:grid-cols-2 gap-6' },
          React.createElement(Card, { className: 'p-5' },
            React.createElement('h3', { className: 'font-semibold text-white mb-4' }, 'Recent Activity'),
            recentActivity.length === 0 ? React.createElement(Empty, { text: 'No recent activity' }) :
            recentActivity.map((a, i) => React.createElement('div', { key: i, className: 'flex items-center justify-between py-2.5 border-b border-gray-800/60 last:border-0' },
              React.createElement('span', { className: 'text-sm text-gray-300 truncate' }, a.text),
              a.severity ? React.createElement(SeverityBadge, { severity: a.severity }) :
              a.status ? React.createElement(StatusBadge, { status: a.status }) : null)),
          React.createElement(Card, { className: 'p-5' },
            React.createElement('h3', { className: 'font-semibold text-white mb-4' }, 'Recent Findings'),
            data.findings.length === 0 ? React.createElement(Empty, { text: 'No findings yet' }) :
            data.findings.slice(-5).reverse().map((f, i) => React.createElement('div', { key: f.id || i, className: 'flex items-center justify-between py-2.5 border-b border-gray-800/60 last:border-0' },
              React.createElement('div', null,
                React.createElement('div', { className: 'text-sm text-gray-300' }, f.title || 'Untitled'),
                f.affected_asset && React.createElement('div', { className: 'text-xs text-gray-500 mono' }, f.affected_asset)),
              React.createElement(SeverityBadge, { severity: f.severity })))))));

    }

    function EngagementsPage({ engagementId, setEngagementId }) {
      const [engagements, setEngagements] = useState([]);
      const [loading, setLoading] = useState(true);
      const [showNew, setShowNew] = useState(false);
      const [form, setForm] = useState({ name: '', target: '', mode: 'bug_bounty', description: '', domains: '', ips: '' });
      const toast = useToast();
      const load = useCallback(async () => {
        try { const r = await api.get('/api/engagements'); setEngagements(r.engagements || []); } catch(e) {}
        setLoading(false);
      }, []);
      useEffect(() => { load(); }, [load]);
      const create = async () => {
        try {
          const r = await api.post('/api/engagements', { name: form.name, target: form.target, mode: form.mode, description: form.description });
          for (const d of form.domains.split('\n').filter(Boolean)) {
            try { await api.post(`/api/scope/${r.id}/rules`, { engagement_id: r.id, rule_type: 'include', asset_type: 'domain', value: d.trim() }); } catch(e) {}
          }
          for (const ip of form.ips.split('\n').filter(Boolean)) {
            try { await api.post(`/api/scope/${r.id}/rules`, { engagement_id: r.id, rule_type: 'include', asset_type: 'ip', value: ip.trim() }); } catch(e) {}
          }
          toast.add('Engagement created', 'success');
          await load();
          setShowNew(false);
          setForm({ name: '', target: '', mode: 'bug_bounty', description: '', domains: '', ips: '' });
        } catch(e) { toast.add('Error: ' + e.message, 'error'); }
      };
      const stopEng = async (id, ev) => {
        ev.stopPropagation();
        try { await api.post(`/api/engagements/${id}/stop`); toast.add('Engagement stopped', 'success'); load(); } catch(e) { toast.add(e.message, 'error'); }
      };
      if (loading) return React.createElement(Loading);
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Engagements', subtitle: 'Manage bug bounty engagements' },
          React.createElement(Btn, { onClick: () => setShowNew(true), color: 'green' }, '+ New')),
        React.createElement(Modal, { open: showNew, onClose: () => setShowNew(false), title: 'New Engagement', wide: true },
          React.createElement('div', { className: 'grid grid-cols-2 gap-3' },
            React.createElement(Input, { label: 'Name', value: form.name, onChange: v => setForm({...form, name: v}), placeholder: 'ACME Bug Bounty' }),
            React.createElement(Input, { label: 'Target', value: form.target, onChange: v => setForm({...form, target: v}), placeholder: 'acme.com' }),
            React.createElement(Select, { label: 'Mode', value: form.mode, onChange: v => setForm({...form, mode: v}), options: [{value:'bug_bounty',label:'Bug Bounty'},{value:'pentest',label:'Pentest'},{value:'analysis_only',label:'Analysis Only'}] }),
            React.createElement(Input, { label: 'Description', value: form.description, onChange: v => setForm({...form, description: v}), placeholder: 'Scope rules...' })),
          React.createElement(TextArea, { label: 'Domains (one per line)', value: form.domains, onChange: v => setForm({...form, domains: v}), placeholder: 'example.com\napi.example.com' }),
          React.createElement(TextArea, { label: 'IPs/CIDRs (one per line)', value: form.ips, onChange: v => setForm({...form, ips: v}), placeholder: '192.168.1.0/24' }),
          React.createElement('div', { className: 'flex gap-2 mt-4' },
            React.createElement(Btn, { onClick: create, color: 'green', disabled: !form.name }, 'Create'),
            React.createElement(Btn, { onClick: () => setShowNew(false), color: 'gray' }, 'Cancel'))),
        React.createElement(Card, { className: 'p-4' },
          engagements.length === 0 ? React.createElement(Empty, { text: 'No engagements yet' }) :
          React.createElement('div', { className: 'space-y-2' },
            engagements.map(e => React.createElement('div', { key: e.id,
              className: `flex items-center justify-between p-4 rounded-xl cursor-pointer transition-all border ${engagementId === e.id ? 'bg-blue-900/20 border-blue-500/30' : 'bg-gray-800/30 border-transparent hover:border-gray-600/40'}`,
              onClick: () => setEngagementId(e.id) },
              React.createElement('div', null,
                React.createElement('div', { className: 'flex items-center gap-2' },
                  React.createElement('span', { className: 'font-semibold text-white' }, e.name),
                  React.createElement(StatusBadge, { status: e.status })),
                React.createElement('div', { className: 'text-xs text-gray-500 mt-1' }, `${e.target || 'No target'} \u00B7 ${e.mode} \u00B7 ${e.id}`)),
              React.createElement('div', { className: 'flex gap-2' },
                React.createElement(Btn, { onClick: (ev) => { ev.stopPropagation(); setEngagementId(e.id); }, color: 'blue', small: true }, 'Select'),
                e.status === 'active' && React.createElement(Btn, { onClick: (ev) => stopEng(e.id, ev), color: 'red', small: true }, 'Stop')))))));
    }

    function ScopeManagerPage({ engagementId }) {
      const [rules, setRules] = useState([]);
      const [loading, setLoading] = useState(true);
      const [showAdd, setShowAdd] = useState(false);
      const [form, setForm] = useState({ rule_type: 'include', asset_type: 'domain', value: '', ports: '', methods: '' });
      const [checkTarget, setCheckTarget] = useState('');
      const toast = useToast();
      const load = useCallback(async () => {
        if (!engagementId) { setLoading(false); return; }
        try { const r = await api.get(`/api/scope/${engagementId}/rules`); setRules(r.rules || []); } catch(e) {}
        setLoading(false);
      }, [engagementId]);
      useEffect(() => { load(); }, [load]);
      const addRule = async () => {
        try {
          await api.post(`/api/scope/${engagementId}/rules`, {
            engagement_id: engagementId, rule_type: form.rule_type, asset_type: form.asset_type,
            value: form.value, ports: form.ports || undefined, methods: form.methods || undefined });
          toast.add('Rule added', 'success');
          setShowAdd(false); setForm({ rule_type: 'include', asset_type: 'domain', value: '', ports: '', methods: '' }); load();
        } catch(e) { toast.add(e.message, 'error'); }
      };
      const deleteRule = async (ruleId) => {
        try { await api.del(`/api/scope/${engagementId}/rules/${ruleId}`); toast.add('Rule deleted', 'success'); load(); } catch(e) { toast.add(e.message, 'error'); }
      };
      if (!engagementId) return React.createElement('div', { className: 'fade-in' }, React.createElement(Empty, { icon: '\u{1F3AF}', text: 'Select an engagement first' }));
      if (loading) return React.createElement(Loading);
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Scope Manager', subtitle: `Engagement: ${engagementId}` },
          React.createElement(Btn, { onClick: () => setShowAdd(true), color: 'green' }, '+ Add Rule')),
        React.createElement(Card, { className: 'p-4 mb-6' },
          React.createElement('h3', { className: 'text-sm font-semibold text-gray-400 mb-3' }, 'Scope Check'),
          React.createElement(ScopeCheckInput, { engagementId, label: 'Check Target', value: checkTarget, onChange: setCheckTarget, placeholder: 'Enter target to check scope...' })),
        React.createElement(Modal, { open: showAdd, onClose: () => setShowAdd(false), title: 'Add Scope Rule' },
          React.createElement(Select, { label: 'Rule Type', value: form.rule_type, onChange: v => setForm({...form, rule_type: v}), options: [{value:'include',label:'Include'},{value:'exclude',label:'Exclude'}] }),
          React.createElement(Select, { label: 'Asset Type', value: form.asset_type, onChange: v => setForm({...form, asset_type: v}), options: [{value:'domain',label:'Domain'},{value:'ip',label:'IP/CIDR'},{value:'url',label:'URL'},{value:'port',label:'Port'},{value:'wildcard',label:'Wildcard'}] }),
          React.createElement(Input, { label: 'Value / Pattern', value: form.value, onChange: v => setForm({...form, value: v}), placeholder: 'example.com or 192.168.1.0/24' }),
          React.createElement(Input, { label: 'Ports (optional)', value: form.ports, onChange: v => setForm({...form, ports: v}), placeholder: '80,443,8080' }),
          React.createElement(Input, { label: 'Methods (optional)', value: form.methods, onChange: v => setForm({...form, methods: v}), placeholder: 'GET,POST' }),
          React.createElement('div', { className: 'flex gap-2 mt-4' },
            React.createElement(Btn, { onClick: addRule, color: 'green', disabled: !form.value }, 'Add'),
            React.createElement(Btn, { onClick: () => setShowAdd(false), color: 'gray' }, 'Cancel'))),
        React.createElement(Card, { className: 'p-4' },
          React.createElement('h3', { className: 'text-sm font-semibold text-gray-400 mb-3' }, `Rules (${rules.length})`),
          rules.length === 0 ? React.createElement(Empty, { text: 'No scope rules defined' }) :
          React.createElement('div', { className: 'space-y-2' },
            rules.map((r, i) => React.createElement('div', { key: r.id || i, className: 'flex items-center justify-between p-3 bg-gray-800/40 rounded-lg' },
              React.createElement('div', { className: 'flex items-center gap-3' },
                React.createElement(Badge, { color: r.rule_type === 'include' ? 'green' : 'red' }, r.rule_type),
                React.createElement(Badge, { color: 'blue' }, r.asset_type),
                React.createElement('span', { className: 'text-sm text-gray-300 mono' }, r.value || r.pattern)),
              React.createElement(Btn, { onClick: () => deleteRule(r.id), color: 'red', small: true }, 'Delete'))))));
    }

    function ReconPage({ engagementId }) {
      const [target, setTarget] = useState('');
      const [results, setResults] = useState({});
      const [running, setRunning] = useState({});
      const [assets, setAssets] = useState([]);
      const toast = useToast();
      useEffect(() => {
        if (engagementId) api.get(`/api/graph/${engagementId}`).then(r => setAssets(r.nodes || [])).catch(() => {});
      }, [engagementId]);
      const tools = [
        { id: 'subdomains', label: 'Subdomain Discovery', tool: 'subfinder', desc: 'Passive subdomain enumeration' },
        { id: 'probe', label: 'HTTP Probe', tool: 'httpx', desc: 'HTTP probing & tech detection' },
        { id: 'portscan', label: 'Port Scan', tool: 'nmap', desc: 'Network port scanning' },
        { id: 'tech', label: 'Tech Fingerprint', tool: 'whatweb', desc: 'Technology fingerprinting' },
        { id: 'crawl', label: 'Web Crawl', tool: 'katana', desc: 'Endpoint & JS discovery' },
        { id: 'fuzz', label: 'Directory Fuzz', tool: 'ffuf', desc: 'Directory & parameter fuzzing' },
        { id: 'portscan-quick', label: 'Quick Ports', tool: 'naabu', desc: 'Fast top-port scanning' },
        { id: 'dns', label: 'DNS Resolution', tool: 'dnsx', desc: 'DNS resolution & enumeration' },
        { id: 'waf', label: 'WAF Detection', tool: 'wafw00f', desc: 'WAF fingerprinting' },
        { id: 'vuln-scan', label: 'Vuln Scan', tool: 'nikto', desc: 'Web vulnerability scanning' },
        { id: 'spider', label: 'Web Spider', tool: 'gospider', desc: 'Deep web crawling' },
        { id: 'mass-scan', label: 'Mass Scan', tool: 'masscan', desc: 'Ultra-fast port scanning' },
      ];
      const runTool = async (toolId) => {
        if (!target) { toast.add('Enter a target', 'warn'); return; }
        setRunning(p => ({...p, [toolId]: true}));
        try {
          const t = tools.find(t => t.id === toolId);
          const r = await api.post(`/api/recon/${toolId}`, { engagement_id: engagementId || '', target, params: {} });
          setResults(p => ({...p, [toolId]: r}));
          toast.add(`${t.tool} completed`, 'success');
          if (engagementId) { const g = await api.get(`/api/graph/${engagementId}`).catch(() => ({nodes:[]})); setAssets(g.nodes || []); }
        } catch(e) { setResults(p => ({...p, [toolId]: {error: e.message}})); toast.add(e.message, 'error'); }
        setRunning(p => ({...p, [toolId]: false}));
      };
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Recon', subtitle: 'Reconnaissance & discovery tools' }),
        React.createElement(Card, { className: 'p-4 mb-6' },
          React.createElement(ScopeCheckInput, { engagementId, label: 'Target', value: target, onChange: setTarget, placeholder: 'target.com or IP' })),
        React.createElement('div', { className: 'grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 mb-6' },
          tools.map(t => React.createElement(Card, { key: t.id, className: 'p-4' },
            React.createElement('div', { className: 'flex items-center justify-between mb-2' },
              React.createElement('div', null,
                React.createElement('div', { className: 'font-medium text-white text-sm' }, t.label),
                React.createElement('div', { className: 'text-xs text-gray-500' }, t.desc)),
              React.createElement(Btn, { onClick: () => runTool(t.id), color: 'blue', small: true, disabled: running[t.id] || !target },
                running[t.id] ? React.createElement('span', { className: 'flex items-center gap-1' },
                  React.createElement('div', { className: 'w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin' }), 'Running') : 'Run')),
            results[t.id] && React.createElement('div', { className: 'mt-3 bg-gray-900/60 rounded-lg p-3 text-xs mono text-gray-300 max-h-40 overflow-y-auto' },
              results[t.id].error
                ? React.createElement('span', { className: 'text-red-400' }, results[t.id].error)
                : React.createElement('pre', { className: 'whitespace-pre-wrap' },
                    JSON.stringify(results[t.id].result?.parsed_output || results[t.id].result || results[t.id], null, 2).slice(0, 800)))))),
        assets.length > 0 && React.createElement(Card, { className: 'p-4' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, `Discovered Assets (${assets.length})`),
          React.createElement('div', { className: 'space-y-1 max-h-64 overflow-y-auto' },
            assets.map((a, i) => React.createElement('div', { key: a.id || i, className: 'flex items-center gap-2 text-xs bg-gray-800/40 rounded-lg px-3 py-1.5' },
              React.createElement(Badge, { color: 'blue' }, a.node_type || a.type || 'asset'),
              React.createElement('span', { className: 'text-gray-300 mono truncate' }, a.label || a.value || JSON.stringify(a)))))));
    }

    function WebSecurityPage({ engagementId }) {
      const [url, setUrl] = useState('');
      const [results, setResults] = useState({});
      const [running, setRunning] = useState({});
      const toast = useToast();
      const checks = [
        { id: 'headers', label: 'Security Headers', endpoint: '/api/web/headers' },
        { id: 'cors', label: 'CORS Analysis', endpoint: '/api/web/cors' },
        { id: 'cookies', label: 'Cookie Analysis', endpoint: '/api/web/cookies' },
        { id: 'js', label: 'JS Analysis', endpoint: '/api/web/js' },
        { id: 'jwt', label: 'JWT Analysis', endpoint: '/api/web/jwt' },
        { id: 'tech', label: 'Tech Detection', endpoint: '/api/web/tech' },
        { id: 'endpoints', label: 'Endpoints', endpoint: '/api/web/endpoints' },
        { id: 'full-scan', label: 'Full Scan', endpoint: '/api/web/full-scan' },
      ];
      const runCheck = async (c) => {
        if (!url) { toast.add('Enter a URL', 'warn'); return; }
        setRunning(p => ({...p, [c.id]: true}));
        try {
          const r = await api.post(c.endpoint, { url, engagement_id: engagementId || '' });
          setResults(p => ({...p, [c.id]: r}));
          toast.add(`${c.label} completed`, 'success');
        } catch(e) { setResults(p => ({...p, [c.id]: {error: e.message}})); toast.add(e.message, 'error'); }
        setRunning(p => ({...p, [c.id]: false}));
      };
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Web Security', subtitle: 'Web application security analysis' }),
        React.createElement(Card, { className: 'p-4 mb-6' },
          React.createElement(ScopeCheckInput, { engagementId, label: 'Target URL', value: url, onChange: setUrl, placeholder: 'https://target.com' }),
          React.createElement('div', { className: 'flex gap-2 flex-wrap' },
            checks.map(c => React.createElement(Btn, { key: c.id, onClick: () => runCheck(c), color: 'blue', small: true, disabled: running[c.id] || !url },
              running[c.id] ? `${c.label}...` : c.label)))),
        checks.filter(c => results[c.id]).map(c => React.createElement(Card, { key: c.id, className: 'p-4 mb-4' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, c.label),
          results[c.id].error
            ? React.createElement('div', { className: 'text-red-400 text-sm' }, results[c.id].error)
            : React.createElement('pre', { className: 'bg-gray-900/60 rounded-lg p-4 text-xs text-gray-300 max-h-80 overflow-y-auto whitespace-pre-wrap mono' },
                JSON.stringify(results[c.id].result || results[c.id], null, 2).slice(0, 5000)))));
    }

    function ApiSecurityPage({ engagementId }) {
      const [url, setUrl] = useState('');
      const [results, setResults] = useState({});
      const [running, setRunning] = useState({});
      const toast = useToast();
      const checks = [
        { id: 'openapi', label: 'OpenAPI Discovery', endpoint: '/api/web/openapi' },
        { id: 'graphql', label: 'GraphQL Introspection', endpoint: '/api/web/graphql' },
        { id: 'auth-scan', label: 'Auth Scan', endpoint: '/api/web/auth-scan' },
        { id: 'idor', label: 'IDOR Testing', endpoint: '/api/web/idor' },
        { id: 'full-scan', label: 'Full API Scan', endpoint: '/api/web/full-scan' },
      ];
      const runCheck = async (c) => {
        if (!url) { toast.add('Enter an API URL', 'warn'); return; }
        setRunning(p => ({...p, [c.id]: true}));
        try {
          const r = await api.post(c.endpoint, { url, engagement_id: engagementId || '' });
          setResults(p => ({...p, [c.id]: r}));
          toast.add(`${c.label} completed`, 'success');
        } catch(e) { setResults(p => ({...p, [c.id]: {error: e.message}})); toast.add(e.message, 'error'); }
        setRunning(p => ({...p, [c.id]: false}));
      };
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'API Security', subtitle: 'API security testing' }),
        React.createElement(Card, { className: 'p-4 mb-6' },
          React.createElement(ScopeCheckInput, { engagementId, label: 'API URL', value: url, onChange: setUrl, placeholder: 'https://target.com/api/v1' }),
          React.createElement('div', { className: 'flex gap-2 flex-wrap' },
            checks.map(c => React.createElement(Btn, { key: c.id, onClick: () => runCheck(c), color: 'purple', small: true, disabled: running[c.id] || !url },
              running[c.id] ? `${c.label}...` : c.label)))),
        checks.filter(c => results[c.id]).map(c => React.createElement(Card, { key: c.id, className: 'p-4 mb-4' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, c.label),
          results[c.id].error
            ? React.createElement('div', { className: 'text-red-400 text-sm' }, results[c.id].error)
            : React.createElement('pre', { className: 'bg-gray-900/60 rounded-lg p-4 text-xs text-gray-300 max-h-80 overflow-y-auto whitespace-pre-wrap mono' },
                JSON.stringify(results[c.id].result || results[c.id], null, 2).slice(0, 5000)))));
    }

    function AuthTestingPage({ engagementId }) {
      const [authData, setAuthData] = useState(null);
      const [diffTest, setDiffTest] = useState({ url: '', method: 'GET', headers_a: '', headers_b: '' });
      const [diffResult, setDiffResult] = useState(null);
      const [loading, setLoading] = useState(true);
      const [testing, setTesting] = useState(false);
      const toast = useToast();
      useEffect(() => {
        if (!engagementId) { setLoading(false); return; }
        api.get(`/api/authorizations/${engagementId}`).then(r => { setAuthData(r); setLoading(false); }).catch(() => setLoading(false));
      }, [engagementId]);
      const runDiffTest = async () => {
        setTesting(true);
        try {
          const hA = {}; diffTest.headers_a.split('\n').filter(Boolean).forEach(l => { const [k,...v] = l.split(':'); if(k) hA[k.trim()] = v.join(':').trim(); });
          const hB = {}; diffTest.headers_b.split('\n').filter(Boolean).forEach(l => { const [k,...v] = l.split(':'); if(k) hB[k.trim()] = v.join(':').trim(); });
          const r = await api.post('/api/auth/diff-test', { url: diffTest.url, method: diffTest.method, headers_a: hA, headers_b: hB });
          setDiffResult(r); toast.add('Diff test completed', 'success');
        } catch(e) { toast.add(e.message, 'error'); }
        setTesting(false);
      };
      if (!engagementId) return React.createElement('div', { className: 'fade-in' }, React.createElement(Empty, { icon: '\u{1F511}', text: 'Select an engagement first' }));
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Authorization Testing', subtitle: 'Differential authorization testing' }),
        React.createElement(Card, { className: 'p-4 mb-6' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'Differential Test'),
          React.createElement('div', { className: 'grid grid-cols-1 md:grid-cols-3 gap-3' },
            React.createElement(Input, { label: 'URL', value: diffTest.url, onChange: v => setDiffTest({...diffTest, url: v}), placeholder: 'https://target.com/api/resource' }),
            React.createElement(Select, { label: 'Method', value: diffTest.method, onChange: v => setDiffTest({...diffTest, method: v}), options: ['GET','POST','PUT','DELETE','PATCH'] }),
            React.createElement('div', { className: 'flex items-end' },
              React.createElement(Btn, { onClick: runDiffTest, color: 'orange', disabled: testing || !diffTest.url, className: 'w-full' }, testing ? 'Testing...' : 'Run Diff Test'))),
          React.createElement('div', { className: 'grid grid-cols-2 gap-3 mt-3' },
            React.createElement(TextArea, { label: 'Headers A (authorized)', value: diffTest.headers_a, onChange: v => setDiffTest({...diffTest, headers_a: v}), placeholder: 'Authorization: Bearer token_a', rows: 3 }),
            React.createElement(TextArea, { label: 'Headers B (unauthorized)', value: diffTest.headers_b, onChange: v => setDiffTest({...diffTest, headers_b: v}), placeholder: 'Authorization: Bearer token_b', rows: 3 }))),
        diffResult && React.createElement(Card, { className: 'p-4 mb-6' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'Result'),
          React.createElement('pre', { className: 'bg-gray-900/60 rounded-lg p-4 text-xs text-gray-300 max-h-80 overflow-y-auto whitespace-pre-wrap mono' },
            JSON.stringify(diffResult, null, 2))),
        React.createElement(Card, { className: 'p-4' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'Authorization Data'),
          loading ? React.createElement(Loading) :
          authData ? React.createElement('pre', { className: 'bg-gray-900/60 rounded-lg p-4 text-xs text-gray-300 max-h-80 overflow-y-auto whitespace-pre-wrap mono' },
            JSON.stringify(authData, null, 2)) :
          React.createElement(Empty, { text: 'No authorization data' })));
    }

    function CtfChallengesPage({ engagementId }) {
      const [challenges, setChallenges] = useState([]);
      const [loading, setLoading] = useState(true);
      const [showNew, setShowNew] = useState(false);
      const [form, setForm] = useState({ name: '', category: 'web', target: '', port: '0', description: '' });
      const [filter, setFilter] = useState('');
      const toast = useToast();
      const categories = ['web','pwn','reverse','crypto','forensics','osint','misc','stego','mobile','blockchain'];
      const load = useCallback(async () => {
        try {
          const url = engagementId ? `/api/ctf/challenges?engagement_id=${engagementId}` : '/api/ctf/challenges';
          const r = await api.get(url); setChallenges(r.challenges || []);
        } catch(e) {}
        setLoading(false);
      }, [engagementId]);
      useEffect(() => { load(); }, [load]);
      const create = async () => {
        try {
          await api.post('/api/ctf/challenges', { engagement_id: engagementId || '', ...form, port: parseInt(form.port) || 0 });
          toast.add('Challenge created', 'success');
          setShowNew(false); setForm({ name: '', category: 'web', target: '', port: '0', description: '' }); load();
        } catch(e) { toast.add(e.message, 'error'); }
      };
      const grouped = {};
      challenges.forEach(c => { const cat = c.category || 'misc'; if (!grouped[cat]) grouped[cat] = []; grouped[cat].push(c); });
      const filtered = filter ? challenges.filter(c => c.category === filter) : challenges;
      if (loading) return React.createElement(Loading);
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'CTF Challenges', subtitle: 'Capture The Flag workspace' },
          React.createElement(Btn, { onClick: () => setShowNew(true), color: 'purple' }, '+ New')),
        React.createElement('div', { className: 'flex gap-2 mb-4 flex-wrap' },
          React.createElement('button', { onClick: () => setFilter(''), className: `px-3 py-1 rounded-lg text-xs font-medium cursor-pointer ${filter === '' ? 'bg-blue-600/20 text-blue-400' : 'text-gray-500 hover:text-gray-300 bg-gray-800/40'}` }, `All (${challenges.length})`),
          categories.filter(c => grouped[c]).map(cat => React.createElement('button', { key: cat, onClick: () => setFilter(cat),
            className: `px-3 py-1 rounded-lg text-xs font-medium cursor-pointer ${filter === cat ? 'bg-purple-600/20 text-purple-400' : 'text-gray-500 hover:text-gray-300 bg-gray-800/40'}` }, `${cat} (${grouped[cat].length})`))),
        React.createElement(Modal, { open: showNew, onClose: () => setShowNew(false), title: 'New Challenge' },
          React.createElement(Input, { label: 'Name', value: form.name, onChange: v => setForm({...form, name: v}), placeholder: 'Challenge name' }),
          React.createElement(Select, { label: 'Category', value: form.category, onChange: v => setForm({...form, category: v}), options: categories }),
          React.createElement(Input, { label: 'Target', value: form.target, onChange: v => setForm({...form, target: v}), placeholder: 'http://target:port' }),
          React.createElement(Input, { label: 'Port', value: form.port, onChange: v => setForm({...form, port: v}) }),
          React.createElement(TextArea, { label: 'Description', value: form.description, onChange: v => setForm({...form, description: v}) }),
          React.createElement('div', { className: 'flex gap-2 mt-4' },
            React.createElement(Btn, { onClick: create, color: 'purple', disabled: !form.name }, 'Create'),
            React.createElement(Btn, { onClick: () => setShowNew(false), color: 'gray' }, 'Cancel'))),
        filtered.length === 0 ? React.createElement(Empty, { icon: '\u{1F9E9}', text: 'No challenges' }) :
        React.createElement('div', { className: 'grid grid-cols-1 md:grid-cols-2 gap-3' },
          filtered.map(c => React.createElement(Card, { key: c.id, className: 'p-4 hover:border-purple-500/30 transition-all' },
            React.createElement('div', { className: 'flex items-center justify-between' },
              React.createElement('div', null,
                React.createElement('div', { className: 'font-semibold text-white' }, c.name),
                React.createElement('div', { className: 'text-xs text-gray-500 mt-1' }, `${c.target || 'No target'} \u00B7 ${c.port || ''}`)),
              React.createElement('div', { className: 'flex gap-2' },
                React.createElement(Badge, { color: 'purple' }, c.category),
                c.confirmed_flag && React.createElement(Badge, { color: 'green' }, 'SOLVED')))))));

    }

    function CtfWorkspacePage({ engagementId }) {
      const [challenges, setChallenges] = useState([]);
      const [selected, setSelected] = useState(null);
      const [cd, setCd] = useState(null);
      const [hypoForm, setHypoForm] = useState({ hypothesis: '', category: '', test_plan: '' });
      const [flagForm, setFlagForm] = useState('');
      const [noteForm, setNoteForm] = useState('');
      const [artifactForm, setArtifactForm] = useState({ name: '', content: '', artifact_type: 'text' });
      const [tab, setTab] = useState('overview');
      const [loading, setLoading] = useState(true);
      const toast = useToast();
      const loadChallenges = useCallback(async () => {
        try {
          const url = engagementId ? `/api/ctf/challenges?engagement_id=${engagementId}` : '/api/ctf/challenges';
          const r = await api.get(url); setChallenges(r.challenges || []);
        } catch(e) {}
        setLoading(false);
      }, [engagementId]);
      useEffect(() => { loadChallenges(); }, [loadChallenges]);
      const selectChallenge = async (c) => {
        setSelected(c);
        try {
          const [detail, ledger] = await Promise.all([
            api.get(`/api/ctf/challenges/${c.id}`).catch(() => c),
            api.get(`/api/ctf/challenges/${c.id}/ledger`).catch(() => ({ hypotheses: [] })),
          ]);
          setCd({ ...detail, ledger });
        } catch(e) { setCd({ ...c, ledger: { hypotheses: [] } }); }
      };
      const addHypothesis = async () => {
        if (!hypoForm.hypothesis) return;
        try { await api.post(`/api/ctf/challenges/${selected.id}/hypothesis`, hypoForm); toast.add('Hypothesis added', 'success'); setHypoForm({ hypothesis: '', category: '', test_plan: '' }); selectChallenge(selected); } catch(e) { toast.add(e.message, 'error'); }
      };
      const submitFlag = async () => {
        if (!flagForm) return;
        try { const r = await api.post(`/api/ctf/challenges/${selected.id}/flag`, { flag: flagForm }); toast.add(r.correct ? 'Flag correct!' : 'Flag incorrect', r.correct ? 'success' : 'warn'); setFlagForm(''); selectChallenge(selected); } catch(e) { toast.add(e.message, 'error'); }
      };
      const confirmFlag = async () => {
        try { await api.post(`/api/ctf/challenges/${selected.id}/confirm`); toast.add('Flag confirmed', 'success'); selectChallenge(selected); } catch(e) { toast.add(e.message, 'error'); }
      };
      const addNote = async () => {
        if (!noteForm) return;
        try { await api.post(`/api/ctf/challenges/${selected.id}/note`, { note: noteForm }); toast.add('Note added', 'success'); setNoteForm(''); selectChallenge(selected); } catch(e) { toast.add(e.message, 'error'); }
      };
      const addArtifact = async () => {
        if (!artifactForm.name) return;
        try { await api.post(`/api/ctf/challenges/${selected.id}/artifact`, artifactForm); toast.add('Artifact added', 'success'); setArtifactForm({ name: '', content: '', artifact_type: 'text' }); selectChallenge(selected); } catch(e) { toast.add(e.message, 'error'); }
      };
      if (loading) return React.createElement(Loading);
      const ledger = cd?.ledger || {};
      return React.createElement('div', { className: 'fade-in flex gap-4', style: { minHeight: '80vh' } },
        React.createElement('div', { className: 'w-64 shrink-0' },
          React.createElement('h3', { className: 'text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3' }, `Challenges (${challenges.length})`),
          React.createElement('div', { className: 'space-y-1 max-h-[80vh] overflow-y-auto' },
            challenges.map(c => React.createElement('div', { key: c.id, onClick: () => selectChallenge(c),
              className: `p-3 rounded-lg cursor-pointer text-sm transition-all border ${selected?.id === c.id ? 'bg-purple-900/20 border-purple-500/30 text-white' : 'bg-gray-800/30 border-transparent hover:border-gray-600/30 text-gray-400'}` },
              React.createElement('div', { className: 'font-medium truncate' }, c.name),
              React.createElement('div', { className: 'text-xs text-gray-600 mt-0.5' }, c.category, c.confirmed_flag ? ' \u2022 Solved' : ''))))),
        React.createElement('div', { className: 'flex-1 min-w-0' },
          !selected ? React.createElement(Empty, { icon: '\u{1F9E9}', text: 'Select a challenge' }) :
          React.createElement('div', null,
            React.createElement('div', { className: 'flex items-center gap-3 mb-4' },
              React.createElement('h2', { className: 'text-xl font-bold text-white' }, selected.name),
              React.createElement(Badge, { color: 'purple' }, selected.category),
              cd?.confirmed_flag && React.createElement(Badge, { color: 'green' }, 'SOLVED')),
            React.createElement(Tabs, { tabs: [{id:'overview',label:'Overview'},{id:'hypotheses',label:'Hypotheses'},{id:'flags',label:'Flags'},{id:'notes',label:'Notes'},{id:'artifacts',label:'Artifacts'}], active: tab, onChange: setTab }),
            tab === 'overview' && React.createElement(Card, { className: 'p-4' },
              React.createElement('div', { className: 'grid grid-cols-2 gap-4 text-sm' },
                React.createElement('div', null, React.createElement('span', { className: 'text-gray-500' }, 'Target: '), React.createElement('span', { className: 'text-white mono' }, cd?.target || 'N/A')),
                React.createElement('div', null, React.createElement('span', { className: 'text-gray-500' }, 'Port: '), React.createElement('span', { className: 'text-white' }, cd?.port || 'N/A')),
                React.createElement('div', { className: 'col-span-2' }, React.createElement('span', { className: 'text-gray-500' }, 'Description: '), React.createElement('span', { className: 'text-gray-300' }, cd?.description || 'None')),
                React.createElement('div', null, React.createElement('span', { className: 'text-gray-500' }, 'Confirmed: '), React.createElement('span', { className: cd?.confirmed_flag ? 'text-green-400 font-bold' : 'text-gray-400' }, cd?.confirmed_flag || 'None')),
                React.createElement('div', null, React.createElement('span', { className: 'text-gray-500' }, 'Hypotheses: '), React.createElement('span', { className: 'text-white' }, (ledger.hypotheses || []).length)))),
            tab === 'hypotheses' && React.createElement(Card, { className: 'p-4' },
              React.createElement('div', { className: 'flex gap-2 mb-3' },
                React.createElement('div', { className: 'flex-1' }, React.createElement(Input, { value: hypoForm.hypothesis, onChange: v => setHypoForm({...hypoForm, hypothesis: v}), placeholder: 'Hypothesis...' })),
                React.createElement(Btn, { onClick: addHypothesis, color: 'purple', disabled: !hypoForm.hypothesis }, 'Add')),
              React.createElement('div', { className: 'grid grid-cols-2 gap-2 mb-3' },
                React.createElement(Input, { value: hypoForm.category, onChange: v => setHypoForm({...hypoForm, category: v}), placeholder: 'Category' }),
                React.createElement(Input, { value: hypoForm.test_plan, onChange: v => setHypoForm({...hypoForm, test_plan: v}), placeholder: 'Test plan' })),
              (ledger.hypotheses || []).length === 0 ? React.createElement(Empty, { text: 'No hypotheses yet' }) :
              (ledger.hypotheses || []).map((h, i) => React.createElement('div', { key: h.id || i, className: 'p-3 bg-gray-800/40 rounded-lg mb-2' },
                React.createElement('div', { className: 'text-sm text-white' }, h.hypothesis),
                React.createElement('div', { className: 'text-xs text-gray-500 mt-1' }, `${h.category || 'uncategorized'} \u00B7 ${h.status || 'candidate'}`)))),
            tab === 'flags' && React.createElement(Card, { className: 'p-4' },
              React.createElement('div', { className: 'flex gap-2 mb-4' },
                React.createElement('div', { className: 'flex-1' }, React.createElement(Input, { value: flagForm, onChange: setFlagForm, placeholder: 'flag{...}' })),
                React.createElement(Btn, { onClick: submitFlag, color: 'green', disabled: !flagForm }, 'Submit'),
                React.createElement(Btn, { onClick: confirmFlag, color: 'blue', disabled: !cd?.confirmed_flag }, 'Confirm')),
              React.createElement('div', { className: 'text-sm mb-3' },
                React.createElement('span', { className: 'text-gray-500' }, 'Confirmed: '),
                React.createElement('span', { className: cd?.confirmed_flag ? 'text-green-400 font-bold' : 'text-gray-400' }, cd?.confirmed_flag || 'None')),
              (cd?.submitted_flags || []).length > 0 && React.createElement('div', null,
                React.createElement('h4', { className: 'text-sm font-medium text-gray-300 mb-2' }, 'Submitted'),
                (cd?.submitted_flags || []).map((f, i) => React.createElement('div', { key: i, className: 'text-xs mono bg-gray-800/60 rounded px-2 py-1 mb-1' }, f.flag || JSON.stringify(f))))),
            tab === 'notes' && React.createElement(Card, { className: 'p-4' },
              React.createElement('div', { className: 'flex gap-2 mb-4' },
                React.createElement('div', { className: 'flex-1' }, React.createElement(Input, { value: noteForm, onChange: setNoteForm, placeholder: 'Add note...' })),
                React.createElement(Btn, { onClick: addNote, color: 'blue', disabled: !noteForm }, 'Add')),
              (cd?.notes || []).length === 0 ? React.createElement(Empty, { text: 'No notes yet' }) :
              (cd?.notes || []).map((n, i) => React.createElement('div', { key: i, className: 'text-sm text-gray-300 bg-gray-800/40 rounded-lg px-3 py-2 mb-2' },
                typeof n === 'string' ? n : n.text || JSON.stringify(n)))),
            tab === 'artifacts' && React.createElement(Card, { className: 'p-4' },
              React.createElement('div', { className: 'flex gap-2 mb-3' },
                React.createElement('div', { className: 'flex-1' }, React.createElement(Input, { value: artifactForm.name, onChange: v => setArtifactForm({...artifactForm, name: v}), placeholder: 'Artifact name' })),
                React.createElement(Select, { value: artifactForm.artifact_type, onChange: v => setArtifactForm({...artifactForm, artifact_type: v}), options: ['text','file','url','screenshot'], className: 'w-32' }),
                React.createElement(Btn, { onClick: addArtifact, color: 'green', disabled: !artifactForm.name }, 'Add')),
              React.createElement(TextArea, { value: artifactForm.content, onChange: v => setArtifactForm({...artifactForm, content: v}), placeholder: 'Content...', rows: 3 }),
              (cd?.artifacts || []).length === 0 ? React.createElement(Empty, { text: 'No artifacts' }) :
              (cd?.artifacts || []).map((a, i) => React.createElement('div', { key: i, className: 'p-3 bg-gray-800/40 rounded-lg mb-2' },
                React.createElement('div', { className: 'flex items-center gap-2 mb-1' },
                  React.createElement('span', { className: 'text-sm font-medium text-white' }, a.name || 'Artifact'),
                  React.createElement(Badge, { color: 'blue' }, a.artifact_type || 'text')),
                a.content && React.createElement('div', { className: 'text-xs text-gray-400 mono mt-1 max-h-24 overflow-y-auto' }, String(a.content).slice(0, 500))))))));
    }

    function CryptoToolsPage() {
      const [mode, setMode] = useState('analyze');
      const [input, setInput] = useState('');
      const [result, setResult] = useState(null);
      const [loading, setLoading] = useState(false);
      const [extra, setExtra] = useState('');
      const toast = useToast();
      const run = async (endpoint, body) => {
        setLoading(true);
        try { const r = await api.post(endpoint, body); setResult(r); toast.add('Analysis complete', 'success'); }
        catch(e) { setResult({ error: e.message }); toast.add(e.message, 'error'); }
        setLoading(false);
      };
      const tools = [
        { id: 'analyze', label: 'Analyze', endpoint: '/api/crypto/analyze', extraLabel: '' },
        { id: 'caesar', label: 'Caesar', endpoint: '/api/crypto/caesar', extraLabel: 'Known shift (0-25)' },
        { id: 'xor', label: 'XOR', endpoint: '/api/crypto/xor', extraLabel: 'XOR key (text or hex)' },
        { id: 'hash', label: 'Hash ID', endpoint: '/api/crypto/hash', extraLabel: '' },
      ];
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Crypto Tools', subtitle: 'Cryptographic analysis' }),
        React.createElement('div', { className: 'flex gap-2 mb-4' },
          tools.map(t => React.createElement('button', { key: t.id, onClick: () => { setMode(t.id); setResult(null); setExtra(''); },
            className: `px-4 py-2 rounded-lg text-sm font-medium cursor-pointer transition-colors ${mode === t.id ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30' : 'bg-gray-800/40 text-gray-500 hover:text-gray-300 border border-transparent'}` }, t.label))),
        React.createElement(Card, { className: 'p-4 mb-4' },
          React.createElement(TextArea, { label: 'Input', value: input, onChange: setInput, placeholder: 'Enter text, hash, or ciphertext...', rows: 4 }),
          tools.find(t => t.id === mode)?.extraLabel && React.createElement(Input, { label: tools.find(t => t.id === mode).extraLabel, value: extra, onChange: setExtra }),
          React.createElement(Btn, { onClick: () => { const t = tools.find(t => t.id === mode); const body = { input }; if (extra) body.extra = extra; run(t.endpoint, body); }, color: 'blue', disabled: loading || !input },
            loading ? 'Analyzing...' : 'Analyze')),
        result && React.createElement(Card, { className: 'p-4' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'Results'),
          result.error
            ? React.createElement('div', { className: 'text-red-400 text-sm' }, result.error)
            : React.createElement('pre', { className: 'bg-gray-900/60 rounded-lg p-4 text-xs text-gray-300 max-h-96 overflow-y-auto whitespace-pre-wrap mono' },
                JSON.stringify(result.result || result, null, 2))));
    }

    function ForensicsToolsPage() {
      const [input, setInput] = useState('');
      const [result, setResult] = useState(null);
      const [loading, setLoading] = useState(false);
      const toast = useToast();
      const analyze = async () => {
        if (!input) return;
        setLoading(true);
        try { const r = await api.post('/api/forensics/analyze', { input }); setResult(r); toast.add('Analysis complete', 'success'); }
        catch(e) { setResult({ error: e.message }); toast.add(e.message, 'error'); }
        setLoading(false);
      };
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Forensics Tools', subtitle: 'File and artifact analysis' }),
        React.createElement(Card, { className: 'p-4 mb-4' },
          React.createElement(TextArea, { label: 'File path, hex data, or content', value: input, onChange: setInput, placeholder: 'Enter file path, hex string, or paste content...', rows: 6 }),
          React.createElement(Btn, { onClick: analyze, color: 'cyan', disabled: loading || !input }, loading ? 'Analyzing...' : 'Analyze')),
        result && React.createElement(Card, { className: 'p-4' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'Results'),
          result.error
            ? React.createElement('div', { className: 'text-red-400 text-sm' }, result.error)
            : React.createElement('pre', { className: 'bg-gray-900/60 rounded-lg p-4 text-xs text-gray-300 max-h-96 overflow-y-auto whitespace-pre-wrap mono' },
                JSON.stringify(result.result || result, null, 2))));
    }

    function ToolManagerPage() {
      const [tools, setTools] = useState({});
      const [loading, setLoading] = useState(true);
      const [filter, setFilter] = useState('');
      const toast = useToast();
      const load = useCallback(async () => {
        try { const r = await api.get('/api/tools-health').catch(() => api.get('/api/tools')); setTools(r.tools || r); } catch(e) {}
        setLoading(false);
      }, []);
      useEffect(() => { load(); }, [load]);
      const recheck = async (name) => {
        try { await api.post(`/api/tools/${name}/recheck`); toast.add(`${name} rechecked`, 'success'); load(); } catch(e) { toast.add(e.message, 'error'); }
      };
      const toolList = Array.isArray(tools) ? tools : Object.entries(tools).map(([name, info]) => ({ name, ...(typeof info === 'object' ? info : { available: info }) }));
      const categories = {};
      toolList.forEach(t => { const cat = t.category || t.group || 'other'; if (!categories[cat]) categories[cat] = []; categories[cat].push(t); });
      const filteredCats = filter ? { [filter]: categories[filter] || [] } : categories;
      if (loading) return React.createElement(Loading);
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Tool Manager', subtitle: `${toolList.length} tools` },
          React.createElement(Btn, { onClick: load, color: 'gray' }, 'Refresh')),
        React.createElement('div', { className: 'flex gap-2 mb-4 flex-wrap' },
          React.createElement('button', { onClick: () => setFilter(''), className: `px-3 py-1 rounded-lg text-xs font-medium cursor-pointer ${filter === '' ? 'bg-blue-600/20 text-blue-400' : 'text-gray-500 hover:text-gray-300 bg-gray-800/40'}` }, 'All'),
          Object.keys(categories).map(cat => React.createElement('button', { key: cat, onClick: () => setFilter(cat),
            className: `px-3 py-1 rounded-lg text-xs font-medium cursor-pointer capitalize ${filter === cat ? 'bg-blue-600/20 text-blue-400' : 'text-gray-500 hover:text-gray-300 bg-gray-800/40'}` }, cat))),
        Object.entries(filteredCats).map(([cat, catTools]) => React.createElement('div', { key: cat, className: 'mb-6' },
          React.createElement('h3', { className: 'text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 capitalize' }, `${cat} (${catTools.length})`),
          React.createElement('div', { className: 'grid grid-cols-1 md:grid-cols-2 gap-2' },
            catTools.map(t => React.createElement(Card, { key: t.name || t.id, className: 'p-3' },
              React.createElement('div', { className: 'flex items-center justify-between' },
                React.createElement('div', null,
                  React.createElement('div', { className: 'text-sm font-medium text-white' }, t.name || t.id),
                  React.createElement('div', { className: 'text-xs text-gray-500' }, t.description || t.binary_path || ''),
                  t.version && React.createElement('div', { className: 'text-xs text-gray-600 mono' }, `v${t.version}`)),
                React.createElement('div', { className: 'flex items-center gap-2' },
                  t.risk_level && React.createElement(Badge, { color: 'gray' }, t.risk_level),
                  React.createElement(Badge, { color: t.available !== false ? 'green' : 'red' }, t.available !== false ? 'Installed' : 'Missing'),
                  React.createElement(Btn, { onClick: () => recheck(t.name || t.id), color: 'gray', small: true }, 'Check')))))))));

    }

    function WorkflowBuilderPage() {
      const [workflows, setWorkflows] = useState([]);
      const [loading, setLoading] = useState(true);
      const [showNew, setShowNew] = useState(false);
      const [form, setForm] = useState({ name: '', steps: '', description: '' });
      const toast = useToast();
      const load = useCallback(async () => {
        try { const r = await api.get('/api/workflows'); setWorkflows(r.workflows || []); } catch(e) {}
        setLoading(false);
      }, []);
      useEffect(() => { load(); }, [load]);
      const save = async () => {
        try {
          await api.post('/api/workflows', { name: form.name, steps: form.steps.split('\n').filter(Boolean), description: form.description });
          toast.add('Workflow saved', 'success'); setShowNew(false); setForm({ name: '', steps: '', description: '' }); load();
        } catch(e) { toast.add(e.message, 'error'); }
      };
      const del = async (id) => { try { await api.del(`/api/workflows/${id}`); toast.add('Deleted', 'success'); load(); } catch(e) { toast.add(e.message, 'error'); } };
      if (loading) return React.createElement(Loading);
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Workflow Builder', subtitle: 'Build custom tool chains' },
          React.createElement(Btn, { onClick: () => setShowNew(true), color: 'green' }, '+ New')),
        React.createElement(Modal, { open: showNew, onClose: () => setShowNew(false), title: 'New Workflow' },
          React.createElement(Input, { label: 'Name', value: form.name, onChange: v => setForm({...form, name: v}), placeholder: 'My Recon Chain' }),
          React.createElement(Input, { label: 'Description', value: form.description, onChange: v => setForm({...form, description: v}) }),
          React.createElement(TextArea, { label: 'Steps (one per line)', value: form.steps, onChange: v => setForm({...form, steps: v}), placeholder: 'subdomains\nprobe\ncrawl', rows: 6 }),
          React.createElement('div', { className: 'flex gap-2 mt-4' },
            React.createElement(Btn, { onClick: save, color: 'green', disabled: !form.name }, 'Save'),
            React.createElement(Btn, { onClick: () => setShowNew(false), color: 'gray' }, 'Cancel'))),
        workflows.length === 0 ? React.createElement(Empty, { text: 'No workflows saved' }) :
        React.createElement('div', { className: 'space-y-3' },
          workflows.map(w => React.createElement(Card, { key: w.id, className: 'p-4' },
            React.createElement('div', { className: 'flex items-center justify-between' },
              React.createElement('div', null,
                React.createElement('div', { className: 'font-semibold text-white' }, w.name),
                React.createElement('div', { className: 'text-xs text-gray-500 mt-1' }, w.description || ''),
                React.createElement('div', { className: 'text-xs text-gray-600 mt-1 mono' }, `Steps: ${(w.steps || []).join(' \u2192 ')}`)),
              React.createElement(Btn, { onClick: () => del(w.id), color: 'red', small: true }, 'Delete'))))));
    }

    function HttpClientModule() {
      const [method, setMethod] = useState('GET');
      const [url, setUrl] = useState('');
      const [headers, setHeaders] = useState('');
      const [body, setBody] = useState('');
      const [response, setResponse] = useState(null);
      const [sending, setSending] = useState(false);
      const [history, setHistory] = useState([]);
      const toast = useToast();
      useEffect(() => { api.get('/api/http/history').then(r => setHistory(r.history || [])).catch(() => {}); }, []);
      const send = async () => {
        if (!url) return; setSending(true);
        try {
          const hdrs = {};
          headers.split('\n').filter(Boolean).forEach(l => { const [k,...v] = l.split(':'); if(k) hdrs[k.trim()] = v.join(':').trim(); });
          const r = await api.post('/api/http/request', { method, url, headers: hdrs, body });
          setResponse(r);
          api.get('/api/http/history').then(h => setHistory(h.history || [])).catch(() => {});
        } catch(e) { setResponse({ error: e.message }); }
        setSending(false);
      };
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'HTTP Client', subtitle: 'Build and send HTTP requests' }),
        React.createElement(Card, { className: 'p-4 mb-4' },
          React.createElement('div', { className: 'flex gap-2 mb-3' },
            React.createElement('div', { className: 'w-32' }, React.createElement(Select, { value: method, onChange: setMethod, options: ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'] })),
            React.createElement('div', { className: 'flex-1' }, React.createElement(Input, { value: url, onChange: setUrl, placeholder: 'https://target.com/path' })),
            React.createElement('div', { className: 'pt-0.5' }, React.createElement(Btn, { onClick: send, color: 'blue', disabled: sending || !url }, sending ? 'Sending...' : 'Send'))),
          React.createElement('div', { className: 'grid grid-cols-2 gap-3' },
            React.createElement(TextArea, { label: 'Headers', value: headers, onChange: setHeaders, placeholder: 'Content-Type: application/json\nAuthorization: Bearer token', rows: 3 }),
            React.createElement(TextArea, { label: 'Body', value: body, onChange: setBody, placeholder: '{"key":"value"}', rows: 3 }))),
        response && React.createElement(Card, { className: 'p-4 mb-4' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'Response'),
          response.error
            ? React.createElement('div', { className: 'text-red-400 text-sm' }, response.error)
            : React.createElement('div', null,
                React.createElement('div', { className: 'flex gap-3 mb-3' },
                  React.createElement(Badge, { color: (response.status_code || 0) < 400 ? 'green' : 'red' }, `${response.status_code || 'N/A'}`),
                  response.duration_ms && React.createElement('span', { className: 'text-xs text-gray-500' }, `${response.duration_ms.toFixed(0)}ms`)),
                React.createElement('pre', { className: 'bg-gray-900/80 rounded-lg p-4 text-xs text-gray-300 max-h-80 overflow-y-auto whitespace-pre-wrap mono' },
                  typeof response.body === 'string' ? response.body.slice(0, 5000) : JSON.stringify(response, null, 2).slice(0, 5000)))),
        history.length > 0 && React.createElement(Card, { className: 'p-4' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'History'),
          history.slice(-20).reverse().map((h, i) => React.createElement('div', { key: i,
            className: 'flex items-center gap-3 text-xs py-2 border-b border-gray-800/60 last:border-0 cursor-pointer hover:text-blue-400',
            onClick: () => { setMethod(h.method || 'GET'); setUrl(h.url || ''); } },
            React.createElement(Badge, { color: 'gray' }, h.method),
            React.createElement('span', { className: 'text-gray-300 truncate flex-1' }, h.url),
            h.status_code && React.createElement(Badge, { color: h.status_code < 400 ? 'green' : 'red' }, h.status_code)))));
    }

    function BrowserModule() {
      const [url, setUrl] = useState('');
      const [screenshot, setScreenshot] = useState('');
      const [cookies, setCookies] = useState([]);
      const [jsCode, setJsCode] = useState('document.title');
      const [jsResult, setJsResult] = useState('');
      const [contextId, setContextId] = useState('');
      const [loading, setLoading] = useState(false);
      const toast = useToast();
      const launch = async () => { try { const r = await api.post('/api/browser/launch'); setContextId(r.context_id || ''); toast.add('Browser launched', 'success'); } catch(e) { toast.add(e.message, 'error'); } };
      const navigate = async () => {
        if (!url) return; setLoading(true);
        try {
          const r = await api.post('/api/browser/navigate', { url, context_id: contextId });
          const cid = r.context_id || contextId; setContextId(cid);
          const s = await api.post('/api/browser/screenshot', { context_id: cid }); setScreenshot(s.screenshot || '');
          const c = await api.get(`/api/browser/cookies?context_id=${cid}`); setCookies(c.cookies || []);
        } catch(e) { toast.add('Error: ' + e.message, 'error'); }
        setLoading(false);
      };
      const execJS = async () => { try { const r = await api.post('/api/browser/js', { script: jsCode, context_id: contextId }); setJsResult(JSON.stringify(r.result || r, null, 2)); } catch(e) { setJsResult(e.message); } };
      const closeB = async () => { try { await api.post('/api/browser/close'); setContextId(''); setScreenshot(''); setCookies([]); toast.add('Browser closed', 'success'); } catch(e) { toast.add(e.message, 'error'); } };
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Browser', subtitle: 'Playwright browser automation' },
          React.createElement(Btn, { onClick: launch, color: 'green', small: true }, 'Launch'),
          React.createElement(Btn, { onClick: closeB, color: 'red', small: true }, 'Close')),
        React.createElement(Card, { className: 'p-4 mb-4' },
          React.createElement('div', { className: 'flex gap-2' },
            React.createElement('div', { className: 'flex-1' }, React.createElement(Input, { value: url, onChange: setUrl, placeholder: 'https://target.com' })),
            React.createElement(Btn, { onClick: navigate, color: 'blue', disabled: loading || !url }, loading ? 'Loading...' : 'Navigate'))),
        React.createElement('div', { className: 'grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4' },
          React.createElement(Card, { className: 'p-4' },
            React.createElement('h3', { className: 'font-semibold text-white mb-2 text-sm' }, 'Screenshot'),
            screenshot
              ? React.createElement('img', { src: `data:image/png;base64,${screenshot}`, className: 'rounded-lg border border-gray-700', style: { maxWidth: '100%' } })
              : React.createElement(Empty, { icon: '\u{1F5A5}', text: 'Navigate to a URL' })),
          React.createElement(Card, { className: 'p-4' },
            React.createElement('h3', { className: 'font-semibold text-white mb-2 text-sm' }, 'JavaScript Console'),
            React.createElement(TextArea, { value: jsCode, onChange: setJsCode, rows: 3 }),
            React.createElement(Btn, { onClick: execJS, color: 'green', small: true, disabled: !contextId || !jsCode }, 'Execute'),
            jsResult && React.createElement('pre', { className: 'bg-gray-900/80 rounded-lg p-2 text-xs text-green-300 mt-2 max-h-40 overflow-y-auto mono' }, jsResult))),
        cookies.length > 0 && React.createElement(Card, { className: 'p-4' },
          React.createElement('h3', { className: 'font-semibold text-white mb-2 text-sm' }, `Cookies (${cookies.length})`),
          React.createElement('div', { className: 'space-y-1 max-h-48 overflow-y-auto' },
            cookies.map((c, i) => React.createElement('div', { key: i, className: 'text-xs bg-gray-800/40 rounded-lg px-3 py-1.5 flex gap-2' },
              React.createElement('span', { className: 'text-blue-400 font-medium' }, c.name || c),
              c.value && React.createElement('span', { className: 'text-gray-500 truncate' }, `= ${String(c.value).slice(0, 60)}`))))));

    }

    function AttackSurfacePage({ engagementId }) {
      const [nodes, setNodes] = useState([]);
      const [edges, setEdges] = useState([]);
      const [loading, setLoading] = useState(false);
      const [filter, setFilter] = useState('');
      const [selectedNode, setSelectedNode] = useState(null);
      useEffect(() => {
        if (!engagementId) return;
        setLoading(true);
        api.get(`/api/graph/${engagementId}`).then(r => { setNodes(r.nodes || []); setEdges(r.edges || []); setLoading(false); }).catch(() => setLoading(false));
      }, [engagementId]);
      if (!engagementId) return React.createElement('div', { className: 'fade-in' }, React.createElement(Empty, { icon: '\u{1F578}', text: 'Select an engagement first' }));
      const filtered = nodes.filter(n => !filter || (n.node_type || n.type || '').toLowerCase().includes(filter.toLowerCase()) || (n.label || '').toLowerCase().includes(filter.toLowerCase()));
      const nodeTypes = [...new Set(nodes.map(n => n.node_type || n.type || 'unknown'))];
      const typeColors = { domain:'#3b82f6', subdomain:'#60a5fa', ip:'#10b981', port:'#f59e0b', service:'#8b5cf6', url:'#ec4899', endpoint:'#f43f5e', technology:'#06b6d4', api:'#a855f7', javascript:'#eab308' };
      const getColor = (type) => typeColors[type] || '#6b7280';
      const positions = filtered.map((n, i) => {
        const angle = (2 * Math.PI * i) / Math.max(filtered.length, 1);
        const r = 200 + (i % 3) * 60;
        return { ...n, px: 400 + r * Math.cos(angle), py: 300 + r * Math.sin(angle) };
      });
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Attack Surface', subtitle: `Engagement: ${engagementId}` }),
        React.createElement(Card, { className: 'p-4 mb-4' },
          React.createElement('div', { className: 'flex gap-3 items-end' },
            React.createElement('div', { className: 'flex-1' }, React.createElement(Input, { label: 'Filter', value: filter, onChange: setFilter, placeholder: 'Filter by type or name...' })),
            React.createElement('div', { className: 'flex gap-2 flex-wrap pb-1' },
              nodeTypes.map(t => React.createElement(Badge, { key: t, color: 'blue' }, `${t} (${nodes.filter(n => (n.node_type || n.type) === t).length})`))))),
        React.createElement('div', { className: 'grid grid-cols-1 lg:grid-cols-3 gap-4' },
          React.createElement(Card, { className: 'p-4 lg:col-span-2' },
            loading ? React.createElement(Loading) :
            filtered.length === 0 ? React.createElement(Empty, { icon: '\u{1F578}', text: 'No nodes. Run recon first.' }) :
            React.createElement('svg', { width: '100%', height: '500', viewBox: '0 0 800 600', className: 'bg-gray-900/40 rounded-lg' },
              edges.map((e, i) => {
                const from = positions.find(n => n.id === e.source || n.id === e.from);
                const to = positions.find(n => n.id === e.target || n.id === e.to);
                if (!from || !to) return null;
                return React.createElement('line', { key: i, x1: from.px, y1: from.py, x2: to.px, y2: to.py, stroke: '#374151', strokeWidth: 1 });
              }),
              positions.map((n, i) => React.createElement('g', { key: n.id || i, onClick: () => setSelectedNode(n), className: 'cursor-pointer' },
                React.createElement('circle', { cx: n.px, cy: n.py, r: 6, fill: getColor(n.node_type || n.type || 'unknown'), opacity: 0.9 }),
                React.createElement('text', { x: n.px, y: n.py - 12, textAnchor: 'middle', fill: '#9ca3af', fontSize: 9, fontFamily: 'monospace' },
                  (n.label || n.value || '').slice(0, 20)))))),
          React.createElement(Card, { className: 'p-4' },
            React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'Node Details'),
            selectedNode ? React.createElement('div', { className: 'text-sm space-y-2' },
              Object.entries(selectedNode).filter(([k]) => !k.startsWith('_') && k !== 'px' && k !== 'py').map(([k, v]) => React.createElement('div', { key: k },
                React.createElement('div', { className: 'text-xs text-gray-500' }, k),
                React.createElement('div', { className: 'text-xs text-gray-300 mono break-all' }, typeof v === 'string' ? v : JSON.stringify(v))))) :
            React.createElement(Empty, { text: 'Click a node' }))));
    }

    function HypothesesPage({ engagementId }) {
      const [hypotheses, setHypotheses] = useState([]);
      const [loading, setLoading] = useState(true);
      const [showNew, setShowNew] = useState(false);
      const [form, setForm] = useState({ hypothesis: '', category: '', target: '', confidence: '', test_plan: '', evidence: '' });
      const toast = useToast();
      const load = useCallback(async () => {
        try { const url = engagementId ? `/api/hypotheses?engagement_id=${engagementId}` : '/api/hypotheses'; const r = await api.get(url); setHypotheses(r.hypotheses || []); } catch(e) {}
        setLoading(false);
      }, [engagementId]);
      useEffect(() => { load(); }, [load]);
      const create = async () => {
        try { await api.post('/api/hypotheses', { ...form, engagement_id: engagementId || '' }); toast.add('Hypothesis created', 'success'); setShowNew(false); setForm({ hypothesis: '', category: '', target: '', confidence: '', test_plan: '', evidence: '' }); load(); } catch(e) { toast.add(e.message, 'error'); }
      };
      const updateStatus = async (id, status) => {
        try { await api.post(`/api/hypotheses/${id}/update`, { validation_status: status }); toast.add(`Hypothesis ${status}`, 'success'); load(); } catch(e) { toast.add(e.message, 'error'); }
      };
      if (loading) return React.createElement(Loading);
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Hypotheses', subtitle: 'Track and validate hypotheses' },
          React.createElement(Btn, { onClick: () => setShowNew(true), color: 'yellow' }, '+ New')),
        React.createElement(Modal, { open: showNew, onClose: () => setShowNew(false), title: 'New Hypothesis' },
          React.createElement(TextArea, { label: 'Hypothesis', value: form.hypothesis, onChange: v => setForm({...form, hypothesis: v}), placeholder: 'Describe your hypothesis...' }),
          React.createElement('div', { className: 'grid grid-cols-2 gap-3' },
            React.createElement(Input, { label: 'Category', value: form.category, onChange: v => setForm({...form, category: v}), placeholder: 'auth, injection...' }),
            React.createElement(Input, { label: 'Target', value: form.target, onChange: v => setForm({...form, target: v}), placeholder: 'Target asset' })),
          React.createElement(Input, { label: 'Test Plan', value: form.test_plan, onChange: v => setForm({...form, test_plan: v}), placeholder: 'How to validate...' }),
          React.createElement(TextArea, { label: 'Evidence', value: form.evidence, onChange: v => setForm({...form, evidence: v}), placeholder: 'Supporting evidence...', rows: 3 }),
          React.createElement('div', { className: 'flex gap-2 mt-4' },
            React.createElement(Btn, { onClick: create, color: 'yellow', disabled: !form.hypothesis }, 'Create'),
            React.createElement(Btn, { onClick: () => setShowNew(false), color: 'gray' }, 'Cancel'))),
        hypotheses.length === 0 ? React.createElement(Empty, { icon: '\u{1F4A1}', text: 'No hypotheses yet' }) :
        React.createElement('div', { className: 'space-y-3' },
          hypotheses.map((h, i) => React.createElement(Card, { key: h.id || i, className: 'p-4' },
            React.createElement('div', { className: 'flex items-center justify-between mb-2' },
              React.createElement('span', { className: 'text-sm text-white font-medium' }, h.hypothesis || 'No text'),
              React.createElement(StatusBadge, { status: h.validation_status || h.status || 'candidate' })),
            React.createElement('div', { className: 'text-xs text-gray-500 mb-2' }, `${h.category || 'uncategorized'} \u00B7 ${h.target || 'N/A'}`),
            h.confidence && React.createElement('div', { className: 'text-xs text-gray-500 mb-2' }, `Confidence: ${h.confidence}`),
            React.createElement('div', { className: 'flex gap-2 mt-2' },
              React.createElement(Btn, { onClick: () => updateStatus(h.id, 'validated'), color: 'green', small: true }, 'Validate'),
              React.createElement(Btn, { onClick: () => updateStatus(h.id, 'rejected'), color: 'red', small: true }, 'Reject'))))));
    }

    function FindingsPage({ engagementId }) {
      const [findings, setFindings] = useState([]);
      const [loading, setLoading] = useState(true);
      const [showNew, setShowNew] = useState(false);
      const [form, setForm] = useState({ title: '', severity: 'informational', confidence: 'none', affected_asset: '', description: '', evidence: '' });
      const [filter, setFilter] = useState('');
      const toast = useToast();
      const load = useCallback(async () => {
        try { const url = engagementId ? `/api/findings?engagement_id=${engagementId}` : '/api/findings'; const r = await api.get(url); setFindings(r.findings || []); } catch(e) {}
        setLoading(false);
      }, [engagementId]);
      useEffect(() => { load(); }, [load]);
      const create = async () => {
        try { await api.post('/api/findings', { ...form, engagement_id: engagementId || '' }); toast.add('Finding created', 'success'); setShowNew(false); setForm({ title: '', severity: 'informational', confidence: 'none', affected_asset: '', description: '', evidence: '' }); load(); } catch(e) { toast.add(e.message, 'error'); }
      };
      const validate = async (id) => { try { await api.post(`/api/findings/${id}/validate`); toast.add('Validated', 'success'); load(); } catch(e) { toast.add(e.message, 'error'); } };
      const reject = async (id) => { try { await api.post(`/api/findings/${id}/reject`); toast.add('Rejected', 'success'); load(); } catch(e) { toast.add(e.message, 'error'); } };
      const filtered = filter ? findings.filter(f => f.severity === filter) : findings;
      if (loading) return React.createElement(Loading);
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Findings', subtitle: 'Security findings' },
          React.createElement(Btn, { onClick: () => setShowNew(true), color: 'red' }, '+ New')),
        React.createElement('div', { className: 'flex gap-2 mb-4 flex-wrap' },
          React.createElement('button', { onClick: () => setFilter(''), className: `px-3 py-1 rounded-lg text-xs font-medium cursor-pointer ${filter === '' ? 'bg-blue-600/20 text-blue-400' : 'text-gray-500 hover:text-gray-300 bg-gray-800/40'}` }, `All (${findings.length})`),
          ['critical','high','medium','low','informational'].map(s => {
            const c = findings.filter(f => f.severity === s).length;
            return c > 0 && React.createElement('button', { key: s, onClick: () => setFilter(s),
              className: `px-3 py-1 rounded-lg text-xs font-medium cursor-pointer ${filter === s ? 'bg-blue-600/20 text-blue-400' : 'text-gray-500 hover:text-gray-300 bg-gray-800/40'}` }, `${s} (${c})`);
          })),
        React.createElement(Modal, { open: showNew, onClose: () => setShowNew(false), title: 'New Finding', wide: true },
          React.createElement('div', { className: 'grid grid-cols-2 gap-3' },
            React.createElement(Input, { label: 'Title', value: form.title, onChange: v => setForm({...form, title: v}), placeholder: 'Finding title' }),
            React.createElement(Select, { label: 'Severity', value: form.severity, onChange: v => setForm({...form, severity: v}), options: ['critical','high','medium','low','informational'] }),
            React.createElement(Input, { label: 'Affected Asset', value: form.affected_asset, onChange: v => setForm({...form, affected_asset: v}) }),
            React.createElement(Select, { label: 'Confidence', value: form.confidence, onChange: v => setForm({...form, confidence: v}), options: [{value:'none',label:'None'},{value:'low',label:'Low'},{value:'medium',label:'Medium'},{value:'high',label:'High'}] })),
          React.createElement(TextArea, { label: 'Description', value: form.description, onChange: v => setForm({...form, description: v}) }),
          React.createElement(TextArea, { label: 'Evidence', value: form.evidence, onChange: v => setForm({...form, evidence: v}), rows: 3 }),
          React.createElement('div', { className: 'flex gap-2 mt-4' },
            React.createElement(Btn, { onClick: create, color: 'red', disabled: !form.title }, 'Create'),
            React.createElement(Btn, { onClick: () => setShowNew(false), color: 'gray' }, 'Cancel'))),
        filtered.length === 0 ? React.createElement(Empty, { text: 'No findings' }) :
        React.createElement('div', { className: 'space-y-3' },
          filtered.map(f => React.createElement(Card, { key: f.id, className: 'p-4' },
            React.createElement('div', { className: 'flex items-center justify-between mb-2' },
              React.createElement('div', null,
                React.createElement('span', { className: 'font-semibold text-white' }, f.title || 'Untitled'),
                f.affected_asset && React.createElement('span', { className: 'text-xs text-gray-500 ml-2 mono' }, f.affected_asset)),
              React.createElement('div', { className: 'flex gap-2' },
                React.createElement(SeverityBadge, { severity: f.severity }),
                f.validation_status && React.createElement(StatusBadge, { status: f.validation_status }))),
            f.description && React.createElement('div', { className: 'text-xs text-gray-400 mb-3' }, f.description),
            React.createElement('div', { className: 'flex gap-2' },
              React.createElement(Btn, { onClick: () => validate(f.id), color: 'green', small: true }, 'Validate'),
              React.createElement(Btn, { onClick: () => reject(f.id), color: 'red', small: true }, 'Reject'))))));
    }

    function EvidencePage({ engagementId }) {
      const [evidence, setEvidence] = useState([]);
      const [loading, setLoading] = useState(true);
      const [selected, setSelected] = useState(null);
      const [filter, setFilter] = useState('');
      useEffect(() => {
        const url = engagementId ? `/api/evidence?engagement_id=${engagementId}` : '/api/evidence';
        api.get(url).then(r => { setEvidence(r.evidence || []); setLoading(false); }).catch(() => setLoading(false));
      }, [engagementId]);
      const filtered = filter ? evidence.filter(e => (e.evidence_type || e.source_tool || '').toLowerCase().includes(filter.toLowerCase())) : evidence;
      if (loading) return React.createElement(Loading);
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Evidence Vault', subtitle: 'Evidence collection & management' }),
        React.createElement(Card, { className: 'p-4 mb-4' },
          React.createElement(Input, { label: 'Filter evidence', value: filter, onChange: setFilter, placeholder: 'Filter by type or source...' })),
        React.createElement('div', { className: 'grid grid-cols-1 lg:grid-cols-3 gap-4' },
          React.createElement(Card, { className: 'p-4 lg:col-span-1' },
            React.createElement('h3', { className: 'text-sm font-semibold text-gray-400 mb-3' }, `Evidence (${filtered.length})`),
            filtered.length === 0 ? React.createElement(Empty, { text: 'No evidence' }) :
            React.createElement('div', { className: 'space-y-1 max-h-[70vh] overflow-y-auto' },
              filtered.map((e, i) => React.createElement('div', { key: e.id || i,
                className: `p-3 rounded-lg cursor-pointer text-sm transition-all border ${selected === i ? 'bg-blue-900/20 border-blue-500/30 text-white' : 'bg-gray-800/30 border-transparent hover:border-gray-600/30 text-gray-400'}`,
                onClick: () => setSelected(i) },
                React.createElement('div', { className: 'font-medium truncate' }, e.evidence_type || e.source_tool || 'Evidence'),
                React.createElement('div', { className: 'text-xs text-gray-600 mt-0.5' }, e.created_at ? new Date(e.created_at).toLocaleString() : ''))))),
          React.createElement(Card, { className: 'p-4 lg:col-span-2' },
            React.createElement('h3', { className: 'text-sm font-semibold text-gray-400 mb-3' }, 'Evidence Detail'),
            selected !== null && filtered[selected]
              ? React.createElement('div', null,
                  React.createElement('div', { className: 'grid grid-cols-2 gap-3 text-sm mb-4' },
                    Object.entries(filtered[selected]).filter(([k]) => k !== 'content' && k !== 'raw_data').map(([k, v]) => React.createElement('div', { key: k },
                      React.createElement('div', { className: 'text-xs text-gray-500' }, k),
                      React.createElement('div', { className: 'text-xs text-gray-300 mono' }, typeof v === 'object' ? JSON.stringify(v) : String(v)))),
                  (filtered[selected].content || filtered[selected].raw_data) && React.createElement('pre', { className: 'bg-gray-900/60 rounded-lg p-4 text-xs text-gray-300 max-h-96 overflow-y-auto whitespace-pre-wrap mono' },
                    typeof (filtered[selected].content || filtered[selected].raw_data) === 'string'
                      ? (filtered[selected].content || filtered[selected].raw_data)
                      : JSON.stringify(filtered[selected].content || filtered[selected].raw_data, null, 2).slice(0, 5000))))

              : React.createElement(Empty, { text: 'Select evidence to view' }))));


    }

    function ReportsPage({ engagementId }) {
      const [reports, setReports] = useState([]);
      const [format, setFormat] = useState('markdown');
      const [report, setReport] = useState('');
      const [generating, setGenerating] = useState(false);
      const [loading, setLoading] = useState(true);
      const toast = useToast();
      useEffect(() => {
        api.get('/api/reports').then(r => { setReports(r.reports || []); setLoading(false); }).catch(() => setLoading(false));
      }, []);
      const generate = async () => {
        if (!engagementId) { toast.add('Select an engagement', 'warn'); return; }
        setGenerating(true);
        try {
          const r = await api.post('/api/reports/generate', { engagement_id: engagementId, format });
          setReport(r.content || r.report?.content || JSON.stringify(r, null, 2));
          toast.add('Report generated', 'success');
          api.get('/api/reports').then(h => setReports(h.reports || [])).catch(() => {});
        } catch(e) { setReport('Error: ' + e.message); toast.add(e.message, 'error'); }
        setGenerating(false);
      };
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Reports', subtitle: 'Generate and manage reports' }),
        React.createElement(Card, { className: 'p-4 mb-6' },
          React.createElement('div', { className: 'flex gap-3 items-end' },
            React.createElement('div', { className: 'flex-1' },
              React.createElement('div', { className: 'mb-3' },
                React.createElement('label', { className: 'block text-xs font-medium text-gray-400 mb-1.5' }, 'Engagement'),
                React.createElement('div', { className: 'text-sm text-gray-300 bg-gray-800/60 rounded-lg px-3 py-2' }, engagementId || 'Select in top bar'))),
            React.createElement('div', { className: 'w-40' },
              React.createElement(Select, { label: 'Format', value: format, onChange: setFormat, options: [{value:'markdown',label:'Markdown'},{value:'html',label:'HTML'},{value:'json',label:'JSON'}] })),
            React.createElement(Btn, { onClick: generate, color: 'green', disabled: generating || !engagementId }, generating ? 'Generating...' : 'Generate'))),
        report && React.createElement(Card, { className: 'p-4 mb-6' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'Generated Report'),
          React.createElement('pre', { className: 'text-xs text-gray-300 bg-gray-900/80 rounded-lg p-4 max-h-[60vh] overflow-y-auto whitespace-pre-wrap' }, report)),
        !loading && reports.length > 0 && React.createElement(Card, { className: 'p-4' },
          React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'Previous Reports'),
          React.createElement('div', { className: 'space-y-2' },
            reports.map((r, i) => React.createElement('div', { key: r.id || i, className: 'flex items-center justify-between p-3 bg-gray-800/40 rounded-lg' },
              React.createElement('div', null,
                React.createElement('div', { className: 'text-sm text-white' }, r.title || r.name || `Report ${i + 1}`),
                React.createElement('div', { className: 'text-xs text-gray-500' }, r.created_at ? new Date(r.created_at).toLocaleString() : '')),
              React.createElement(Badge, { color: 'blue' }, r.format || 'markdown'))))));
    }

    function JobCenterPage() {
      const [jobs, setJobs] = useState([]);
      const [loading, setLoading] = useState(true);
      const [filter, setFilter] = useState('');
      const [selectedJob, setSelectedJob] = useState(null);
      const toast = useToast();
      const load = useCallback(async () => {
        try { const r = await api.get('/api/jobs'); setJobs(r.jobs || []); } catch(e) {}
        setLoading(false);
      }, []);
      useEffect(() => { load(); }, [load]);
      useEffect(() => {
        const interval = setInterval(() => {
          api.get('/api/jobs').then(r => setJobs(r.jobs || [])).catch(() => {});
        }, 5000);
        return () => clearInterval(interval);
      }, []);
      const cancel = async (id) => {
        try { await api.post(`/api/jobs/${id}/cancel`); toast.add('Job cancelled', 'success'); load(); } catch(e) { toast.add(e.message, 'error'); }
      };
      const retry = async (id) => {
        try { await api.post(`/api/jobs/${id}/retry`); toast.add('Job retrying', 'success'); load(); } catch(e) { toast.add(e.message, 'error'); }
      };
      const filtered = filter ? jobs.filter(j => j.status === filter) : jobs;
      if (loading) return React.createElement(Loading);
      const statusCounts = {};
      jobs.forEach(j => { statusCounts[j.status] = (statusCounts[j.status] || 0) + 1; });
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Job Center', subtitle: 'Real-time job monitoring' },
          React.createElement(Btn, { onClick: load, color: 'gray' }, 'Refresh')),
        React.createElement('div', { className: 'flex gap-2 mb-4 flex-wrap' },
          React.createElement('button', { onClick: () => setFilter(''), className: `px-3 py-1 rounded-lg text-xs font-medium cursor-pointer ${filter === '' ? 'bg-blue-600/20 text-blue-400' : 'text-gray-500 hover:text-gray-300 bg-gray-800/40'}` }, `All (${jobs.length})`),
          Object.entries(statusCounts).map(([s, c]) => React.createElement('button', { key: s, onClick: () => setFilter(s),
            className: `px-3 py-1 rounded-lg text-xs font-medium cursor-pointer ${filter === s ? 'bg-blue-600/20 text-blue-400' : 'text-gray-500 hover:text-gray-300 bg-gray-800/40'}` }, `${s} (${c})`))),
        React.createElement('div', { className: 'grid grid-cols-1 lg:grid-cols-3 gap-4' },
          React.createElement(Card, { className: 'p-4 lg:col-span-2' },
            filtered.length === 0 ? React.createElement(Empty, { icon: '\u26A1', text: 'No jobs' }) :
            React.createElement('div', { className: 'space-y-2' },
              filtered.map((j, i) => React.createElement('div', { key: j.id || i,
                className: `p-4 rounded-xl cursor-pointer transition-all border ${selectedJob === i ? 'bg-blue-900/20 border-blue-500/30' : 'bg-gray-800/30 border-transparent hover:border-gray-600/30'}`,
                onClick: () => setSelectedJob(i) },
                React.createElement('div', { className: 'flex items-center justify-between mb-1' },
                  React.createElement('span', { className: 'font-medium text-white text-sm' }, j.tool_name || j.workflow || 'job'),
                  React.createElement(StatusBadge, { status: j.status })),
                React.createElement('div', { className: 'text-xs text-gray-500' },
                  j.target && React.createElement('span', { className: 'mono' }, j.target, ' \u00B7 '),
                  j.started_at && new Date(j.started_at).toLocaleTimeString()))))),
          React.createElement(Card, { className: 'p-4' },
            React.createElement('h3', { className: 'font-semibold text-white mb-3' }, 'Job Detail'),
            selectedJob !== null && filtered[selectedJob]
              ? React.createElement('div', { className: 'text-sm space-y-2' },
                  Object.entries(filtered[selectedJob]).map(([k, v]) => React.createElement('div', { key: k },
                    React.createElement('div', { className: 'text-xs text-gray-500' }, k),
                    React.createElement('div', { className: 'text-xs text-gray-300 mono break-all' }, typeof v === 'object' ? JSON.stringify(v) : String(v)))),
                  React.createElement('div', { className: 'flex gap-2 mt-4' },
                    ['failed', 'cancelled'].includes(filtered[selectedJob].status) && React.createElement(Btn, { onClick: () => retry(filtered[selectedJob].id), color: 'blue', small: true }, 'Retry'),
                    ['running', 'queued', 'pending'].includes(filtered[selectedJob].status) && React.createElement(Btn, { onClick: () => cancel(filtered[selectedJob].id), color: 'red', small: true }, 'Cancel')))
              : React.createElement(Empty, { text: 'Select a job' }))));
    }

    function SettingsPage() {
      const [system, setSystem] = useState(null);
      const [loading, setLoading] = useState(true);
      useEffect(() => { api.get('/api/system').then(r => { setSystem(r); setLoading(false); }).catch(() => setLoading(false)); }, []);
      if (loading) return React.createElement(Loading);
      return React.createElement('div', { className: 'fade-in' },
        React.createElement(PageHeader, { title: 'Settings', subtitle: 'System configuration' }),
        React.createElement(Card, { className: 'p-4' },
          system ? React.createElement('div', { className: 'space-y-0' },
            Object.entries(system).map(([k, v]) => React.createElement('div', { key: k, className: 'flex justify-between py-3 border-b border-gray-800/60 last:border-0' },
              React.createElement('span', { className: 'text-sm text-gray-400' }, k),
              React.createElement('span', { className: 'text-sm text-white mono max-w-[60%] text-right truncate' }, typeof v === 'object' ? JSON.stringify(v) : String(v))))
          ) : React.createElement(Empty, { text: 'No system data' })));
    }

    function Sidebar({ page, setPage, collapsed, setCollapsed }) {
      const [openGroups, setOpenGroups] = useState({ bugbounty: true });
      const toggleGroup = (id) => setOpenGroups(p => ({...p, [id]: !p[id]}));
      return React.createElement('nav', { className: `bg-[#111827] border-r border-gray-800/60 flex flex-col shrink-0 transition-all ${collapsed ? 'w-16' : 'w-60'}` },
        React.createElement('div', { className: 'p-4 border-b border-gray-800/60 flex items-center justify-between' },
          !collapsed && React.createElement('div', null,
            React.createElement('h1', { className: 'text-lg font-bold text-white' }, 'SENTINEL'),
            React.createElement('p', { className: 'text-[10px] text-gray-500 mt-0.5' }, 'Security Platform v0.1.0')),
          React.createElement('button', { onClick: () => setCollapsed(!collapsed), className: 'text-gray-500 hover:text-white text-sm' }, collapsed ? '\u25B6' : '\u25C0')),
        React.createElement('div', { className: 'flex-1 overflow-y-auto py-2' },
          NAV_GROUPS.map(group => React.createElement('div', { key: group.id, className: 'mb-1' },
            React.createElement('button', { onClick: () => toggleGroup(group.id),
              className: `w-full text-left px-4 py-2 text-xs font-semibold uppercase tracking-wider flex items-center gap-2 ${collapsed ? 'justify-center' : ''} text-gray-500 hover:text-gray-300` },
              React.createElement('span', null, group.icon),
              !collapsed && React.createElement('span', null, group.label)),
            !collapsed && openGroups[group.id] && React.createElement('div', { className: 'ml-3 space-y-0.5' },
              group.pages.map(p => React.createElement('button', { key: p.id, onClick: () => setPage(p.id),
                className: `w-full text-left px-3 py-1.5 rounded-lg text-sm transition-all ${page === p.id ? 'bg-blue-600/15 text-blue-400 border border-blue-500/20' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/40'}` }, p.label)))))),
        React.createElement('div', { className: 'p-3 border-t border-gray-800/60' },
          React.createElement(WSIndicator, null)));
    }

    function WSIndicator() {
      const { connected } = useContext(WSContext);
      return React.createElement('div', { className: 'flex items-center gap-2 text-xs' },
        React.createElement('span', { className: `w-2 h-2 rounded-full ${connected ? 'bg-green-500 pulse-dot' : 'bg-red-500'}` }),
        React.createElement('span', { className: 'text-gray-500' }, connected ? 'Connected' : 'Disconnected'));
    }

    function TopBar({ engagementId, setEngagementId }) {
      const [engagements, setEngagements] = useState([]);
      useEffect(() => { api.get('/api/engagements').then(r => setEngagements(r.engagements || [])).catch(() => {}); }, []);
      return React.createElement('div', { className: 'h-12 bg-[#111827]/80 border-b border-gray-800/60 flex items-center justify-between px-6' },
        React.createElement('div', { className: 'flex items-center gap-4' },
          React.createElement('span', { className: 'text-xs text-gray-500' }, 'SENTINEL v0.1.0')),
        React.createElement('div', { className: 'flex items-center gap-3' },
          React.createElement('label', { className: 'text-xs text-gray-500' }, 'Engagement:'),
          React.createElement('select', { value: engagementId || '', onChange: e => setEngagementId(e.target.value),
            className: 'bg-gray-800/80 border border-gray-600/60 rounded-lg px-3 py-1.5 text-xs text-white focus:border-blue-500' },
            React.createElement('option', { value: '' }, 'None'),
            engagements.map(e => React.createElement('option', { key: e.id, value: e.id }, `${e.name} (${e.status})`)))));
    }

    function App() {
      const [page, setPage] = useState('bb-dashboard');
      const [engagementId, setEngagementId] = useState('');
      const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
      const navigate = (p) => setPage(p);

      const pageMap = {
        'bb-dashboard': () => React.createElement(DashboardHome, { setPage }),
        'engagements': () => React.createElement(EngagementsPage, { engagementId, setEngagementId }),
        'scope': () => React.createElement(ScopeManagerPage, { engagementId }),
        'recon': () => React.createElement(ReconPage, { engagementId }),
        'web-security': () => React.createElement(WebSecurityPage, { engagementId }),
        'api-security': () => React.createElement(ApiSecurityPage, { engagementId }),
        'auth-testing': () => React.createElement(AuthTestingPage, { engagementId }),
        'ctf-challenges': () => React.createElement(CtfChallengesPage, { engagementId }),
        'ctf-workspace': () => React.createElement(CtfWorkspacePage, { engagementId }),
        'crypto-tools': () => React.createElement(CryptoToolsPage),
        'forensics-tools': () => React.createElement(ForensicsToolsPage),
        'tool-manager': () => React.createElement(ToolManagerPage),
        'workflow-builder': () => React.createElement(WorkflowBuilderPage),
        'http-client': () => React.createElement(HttpClientModule),
        'browser-ws': () => React.createElement(BrowserModule),
        'attack-surface': () => React.createElement(AttackSurfacePage, { engagementId }),
        'hypotheses': () => React.createElement(HypothesesPage, { engagementId }),
        'findings': () => React.createElement(FindingsPage, { engagementId }),
        'evidence': () => React.createElement(EvidencePage, { engagementId }),
        'reports': () => React.createElement(ReportsPage, { engagementId }),
        'job-center': () => React.createElement(JobCenterPage),
        'settings': () => React.createElement(SettingsPage),
      };

      const PageComponent = pageMap[page] || (() => React.createElement(DashboardHome, { setPage }));

      return React.createElement(WSProvider, null,
        React.createElement(ToastProvider, null,
          React.createElement('div', { className: 'flex h-screen' },
            React.createElement(Sidebar, { page, setPage, collapsed: sidebarCollapsed, setCollapsed: setSidebarCollapsed }),
            React.createElement('div', { className: 'flex-1 flex flex-col min-w-0' },
              React.createElement(TopBar, { engagementId, setEngagementId }),
              React.createElement('main', { className: 'flex-1 overflow-y-auto p-6' },
                React.createElement(PageComponent))))));
    }

    ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(App));
    </script>
</body>
</html>
"""
