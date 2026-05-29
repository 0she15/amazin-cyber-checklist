"use client"
import { useState, useEffect, useRef } from "react"

const STORAGE_KEY = "amazin_checklists"

// ── CHECKLIST DATA ─────────────────────────────────────────────────────────
const SECTIONS = [
  {
    id: "mfa",
    label: "MFA + Sign-In Risk",
    severity: "critical",
    icon: "🔐",
    desc: "Highest-impact section. Account takeover starts here.",
    checks: [
      { id: "mfa_all",       label: "MFA enabled for all users",                          severity: "critical", note: "List any users with MFA disabled" },
      { id: "mfa_method",    label: "MFA method quality — authenticator app (not SMS)",    severity: "high",     note: "SMS is better than nothing but weaker than app-based" },
      { id: "mfa_admins",    label: "All admin accounts have MFA enforced",                severity: "critical", note: "Admin accounts without MFA = critical finding" },
      { id: "risky_signins", label: "No risky sign-ins in last 30 days (Entra ID)",        severity: "critical", note: "Check Entra ID Protection → Risky sign-ins" },
      { id: "geo_signins",   label: "No sign-ins from unexpected countries or IPs",        severity: "high",     note: "Flag anything outside normal operating regions" },
      { id: "legacy_auth",   label: "Legacy authentication protocols blocked",             severity: "high",     note: "Basic Auth bypasses MFA — should be disabled" },
    ],
  },
  {
    id: "admin",
    label: "Admin Roles + Permissions",
    severity: "critical",
    icon: "👤",
    desc: "Overpermissioned admins are a primary attack target.",
    checks: [
      { id: "admin_count",    label: "Global Admin count is 2–4 maximum",                  severity: "critical", note: "More than 4 Global Admins is a red flag" },
      { id: "admin_accounts", label: "Global Admins use dedicated admin accounts",         severity: "high",     note: "Admin accounts should be separate from daily email use" },
      { id: "admin_mfa",      label: "All admin accounts are MFA-protected",               severity: "critical", note: "Verify this separately from general MFA check" },
      { id: "service_accts",  label: "No service accounts with unnecessary admin roles",   severity: "high",     note: "Service accounts often accumulate unused permissions" },
      { id: "pim",            label: "Privileged Identity Management (PIM) in use",        severity: "medium",   note: "N/A if Business Basic/Standard — requires P2 license" },
      { id: "stale_admins",   label: "No stale or former-employee admin accounts active",  severity: "critical", note: "Check for accounts that should have been offboarded" },
    ],
  },
  {
    id: "email",
    label: "Email Security (SPF / DKIM / DMARC)",
    severity: "critical",
    icon: "✉️",
    desc: "Email is the #1 attack vector. These records prevent spoofing and phishing.",
    checks: [
      { id: "spf",           label: "SPF record exists and is correctly configured",       severity: "critical", note: "Check with mxtoolbox.com — should end in -all not ~all" },
      { id: "dkim",          label: "DKIM enabled in Exchange Online",                     severity: "critical", note: "Admin center → Exchange → Email authentication" },
      { id: "dmarc",         label: "DMARC record exists",                                 severity: "critical", note: "Even p=none is a start — p=reject is the goal" },
      { id: "dmarc_policy",  label: "DMARC policy is quarantine or reject (not none)",     severity: "high",     note: "p=none provides visibility only — no protection" },
      { id: "antiphish",     label: "Anti-phishing policy configured",                     severity: "high",     note: "Defender for Office 365 → Anti-phishing policies" },
      { id: "antispoofing",  label: "Anti-spoofing protection enabled",                    severity: "high",     note: "Part of anti-phishing policy settings" },
      { id: "safelinks",     label: "Safe Links enabled (requires Defender P1/P2)",        severity: "medium",   note: "N/A if Business Basic — requires Business Premium or add-on" },
      { id: "safeattach",    label: "Safe Attachments enabled (requires Defender P1/P2)",  severity: "medium",   note: "N/A if Business Basic — requires Business Premium or add-on" },
    ],
  },
  {
    id: "conditional",
    label: "Conditional Access + Secure Score",
    severity: "high",
    icon: "🛡️",
    desc: "Requires AAD P1 or Business Premium. Note license level before flagging gaps.",
    checks: [
      { id: "ca_exists",     label: "At least one Conditional Access policy is active",    severity: "high",     note: "N/A if Business Basic/Standard — requires P1 or higher" },
      { id: "ca_mfa",        label: "CA policy enforces MFA for all users",                severity: "high",     note: "Preferred over per-user MFA — more flexible and auditable" },
      { id: "ca_block_legacy", label: "CA policy blocks legacy authentication",            severity: "high",     note: "Legacy auth bypass is one of the most common attack vectors" },
      { id: "ca_admin",      label: "Stricter CA policy applied to admin accounts",        severity: "medium",   note: "Admins should have tighter controls than regular users" },
      { id: "secure_score",  label: "Microsoft Secure Score reviewed",                     severity: "medium",   note: "Note current score and top 3 recommended actions" },
      { id: "defender_end",  label: "Microsoft Defender for Endpoint enrolled (if applicable)", severity: "medium", note: "N/A if no managed endpoints — requires Business Premium" },
    ],
  },
  {
    id: "mailbox",
    label: "Mailbox Rules + Forwarding",
    severity: "high",
    icon: "📬",
    desc: "Attackers set these up after compromise to silently intercept mail.",
    checks: [
      { id: "ext_forward",   label: "No mailboxes forwarding to external addresses",       severity: "critical", note: "Auto-forwarding to external domains = active or past compromise indicator" },
      { id: "inbox_rules",   label: "No suspicious inbox rules (delete-before-read, hidden forward)", severity: "critical", note: "Check all mailboxes, not just the primary contact" },
      { id: "shared_mbox",   label: "Shared mailboxes have no active user logins",         severity: "high",     note: "Shared mailboxes should not have direct sign-in enabled" },
      { id: "shared_mfa",    label: "Shared mailbox access is via delegation only",        severity: "high",     note: "Direct login to shared mailboxes bypasses MFA" },
      { id: "transport",     label: "No unauthorized mail transport rules",                severity: "critical", note: "Check Exchange admin → Mail flow → Rules for unexpected entries" },
      { id: "quarantine",    label: "Quarantine policy reviewed — no unreviewed releases", severity: "medium",   note: "Check that admins are reviewing quarantine regularly" },
    ],
  },
]

const SEVERITY_META = {
  critical: { label: "Critical", color: "text-red-400",    border: "border-red-500/30",    bg: "bg-red-500/10"    },
  high:     { label: "High",     color: "text-amber-400",  border: "border-amber-500/30",  bg: "bg-amber-500/10"  },
  medium:   { label: "Medium",   color: "text-blue-400",   border: "border-blue-500/30",   bg: "bg-blue-500/10"   },
}

const RESULT_META = {
  pass: { label: "Pass", color: "text-green-400",  border: "border-green-500/40",  bg: "bg-green-500/10"  },
  fail: { label: "Fail", color: "text-red-400",    border: "border-red-500/40",    bg: "bg-red-500/10"    },
  na:   { label: "N/A",  color: "text-slate-400",  border: "border-slate-500/30",  bg: "bg-slate-500/10"  },
}

// ── HELPERS ────────────────────────────────────────────────────────────────
function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 6) }
function formatDate(iso) {
  if (!iso) return ""
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
}
function formatDuration(ms) {
  const m = Math.floor(ms / 60000)
  const s = Math.floor((ms % 60000) / 1000)
  return `${m}m ${s.toString().padStart(2, "0")}s`
}
function calcProgress(checks) {
  const total = SECTIONS.reduce((n, s) => n + s.checks.length, 0)
  const done = Object.values(checks || {}).filter(v => v.result).length
  return Math.round((done / total) * 100)
}
function calcScore(checks) {
  let pass = 0, fail = 0
  SECTIONS.forEach(s => s.checks.forEach(c => {
    const r = checks?.[c.id]?.result
    if (r === "pass") pass++
    if (r === "fail") fail++
  }))
  return { pass, fail, total: pass + fail }
}

// ── EXPORT BUILDER (kept for reference / future use) ───────────────────────
function buildExport(engagement) {
  const lines = []
  lines.push(`AMAZIN CYBER — M365 SECURITY SNAPSHOT`)
  lines.push(`Client: ${engagement.clientName || "Unknown"}`)
  lines.push(`Company: ${engagement.company || "Unknown"}`)
  lines.push(`Package: ${engagement.package || "Unknown"}`)
  lines.push(`Reviewed: ${formatDate(engagement.createdAt)}`)
  lines.push(`Duration: ${engagement.duration ? formatDuration(engagement.duration) : "Not recorded"}`)
  lines.push(``)

  const { pass, fail } = calcScore(engagement.checks)
  lines.push(`SUMMARY: ${pass} Pass / ${fail} Fail / ${Object.values(engagement.checks || {}).filter(v => v.result === "na").length} N/A`)
  lines.push(``)

  SECTIONS.forEach(section => {
    lines.push(`── ${section.label.toUpperCase()} ──`)
    section.checks.forEach(check => {
      const r = engagement.checks?.[check.id]
      const result = r?.result ? r.result.toUpperCase() : "NOT CHECKED"
      const sev = SEVERITY_META[check.severity]?.label || check.severity
      lines.push(`[${result}] [${sev}] ${check.label}`)
      if (r?.notes) lines.push(`  Notes: ${r.notes}`)
    })
    lines.push(``)
  })

  return lines.join("\n")
}

export default function Checklist() {
  const [engagements, setEngagements] = useState([])
  const [loaded, setLoaded] = useState(false)
  const [view, setView] = useState("list") // list | active | new
  const [activeId, setActiveId] = useState(null)
  const [showExport, setShowExport] = useState(false)
  const [timerRunning, setTimerRunning] = useState(false)
  const [newForm, setNewForm] = useState({ clientName: "", company: "", package: "Business Snapshot — $500", licenseType: "", userCount: "", notes: "" })
  const timerRef = useRef(null)

  // Load
  useEffect(() => {
    try { const s = localStorage.getItem(STORAGE_KEY); if (s) setEngagements(JSON.parse(s)) } catch {}
    setLoaded(true)
  }, [])

  // Save
  useEffect(() => {
    if (loaded) try { localStorage.setItem(STORAGE_KEY, JSON.stringify(engagements)) } catch {}
  }, [engagements, loaded])

  // Timer
  useEffect(() => {
    if (timerRunning && activeId) {
      timerRef.current = setInterval(() => {
        setEngagements(es => es.map(e => e.id === activeId
          ? { ...e, duration: (e.duration || 0) + 1000 }
          : e
        ))
      }, 1000)
    } else {
      clearInterval(timerRef.current)
    }
    return () => clearInterval(timerRef.current)
  }, [timerRunning, activeId])

  const active = engagements.find(e => e.id === activeId)

  const createEngagement = () => {
    if (!newForm.clientName || !newForm.company) { alert("Client name and company are required."); return }
    const eng = {
      id: uid(),
      ...newForm,
      checks: {},
      duration: 0,
      createdAt: new Date().toISOString(),
      completedAt: null,
    }
    setEngagements(es => [eng, ...es])
    setActiveId(eng.id)
    setView("active")
    setTimerRunning(true)
    setNewForm({ clientName: "", company: "", package: "Business Snapshot — $500", licenseType: "", userCount: "", notes: "" })
  }

  const setCheckResult = (checkId, result) => {
    setEngagements(es => es.map(e => e.id === activeId
      ? { ...e, checks: { ...e.checks, [checkId]: { ...e.checks?.[checkId], result } } }
      : e
    ))
  }

  const setCheckNotes = (checkId, notes) => {
    setEngagements(es => es.map(e => e.id === activeId
      ? { ...e, checks: { ...e.checks, [checkId]: { ...e.checks?.[checkId], notes } } }
      : e
    ))
  }

  const updateEngagementField = (field, val) => {
    setEngagements(es => es.map(e => e.id === activeId ? { ...e, [field]: val } : e))
  }

  const deleteEngagement = (id) => {
    setEngagements(es => es.filter(e => e.id !== id))
    if (activeId === id) { setActiveId(null); setView("list") }
  }

  if (!loaded) return (
    <div className="min-h-screen bg-[#080d14] flex items-center justify-center">
      <p className="text-[13px] font-mono text-[#3d5a7a] animate-pulse">Loading checklists…</p>
    </div>
  )

  return (
    <div className="min-h-screen bg-[#080d14] text-[#e8f0fe]"
      style={{ backgroundImage: "linear-gradient(rgba(59,130,246,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,.018) 1px,transparent 1px)", backgroundSize: "32px 32px" }}>

      {/* Header */}
      <div className="border-b border-[#1a2d45] px-5 py-4 sticky top-0 z-40 bg-[#080d14]/95 backdrop-blur-sm">
        <div className="max-w-4xl mx-auto flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-[#1e3a5f] flex items-center justify-center">
              <svg viewBox="0 0 24 24" fill="none" className="w-4 h-4">
                <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6"/>
                <path d="M9 12l2 2 4-4" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <div>
              <p className="text-[11px] font-mono text-[#60a5fa] uppercase tracking-widest">Amazin Cyber</p>
              <p className="text-[15px] font-semibold leading-tight">M365 Security Checklist</p>
            </div>
          </div>

          {/* Timer strip when active */}
          {view === "active" && active && (
            <div className="flex items-center gap-3">
              <div className="bg-[#0d1520] border border-[#1a2d45] rounded-lg px-3 py-1.5 flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${timerRunning ? "bg-green-400 animate-pulse" : "bg-[#3d5a7a]"}`}/>
                <span className="text-[13px] font-mono text-[#e8f0fe]">{formatDuration(active.duration || 0)}</span>
              </div>
              <button onClick={() => setTimerRunning(r => !r)}
                className={`text-[11px] font-mono px-3 py-1.5 rounded-lg border transition-colors ${timerRunning ? "text-amber-400 border-amber-500/30 bg-amber-500/10" : "text-green-400 border-green-500/30 bg-green-500/10"}`}>
                {timerRunning ? "⏸ Pause" : "▶ Resume"}
              </button>
            </div>
          )}

          <div className="flex items-center gap-2">
            {view === "active" && (
              <>
                <button onClick={() => { setShowExport(true); setTimerRunning(false) }}
                  className="text-[13px] font-mono text-white bg-green-600 px-4 py-2 rounded-lg hover:bg-green-700 transition-colors">
                  Generate Report
                </button>
                <button onClick={() => { setView("list"); setTimerRunning(false) }}
                  className="text-[13px] font-mono text-[#7a9abf] border border-[#1a2d45] px-4 py-2 rounded-lg hover:text-[#e8f0fe] hover:border-[#1e3a5f] transition-colors">
                  ← All Reviews
                </button>
              </>
            )}
            {view === "list" && (
              <button onClick={() => setView("new")}
                className="text-[13px] font-mono text-white bg-[#3b82f6] px-4 py-2 rounded-lg hover:bg-[#2563eb] transition-colors">
                + New Review
              </button>
            )}
            {view === "new" && (
              <button onClick={() => setView("list")}
                className="text-[13px] font-mono text-[#7a9abf] border border-[#1a2d45] px-4 py-2 rounded-lg hover:text-[#e8f0fe] transition-colors">
                ← Cancel
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="max-w-4xl mx-auto px-5 py-6">

        {/* ── NEW REVIEW FORM ── */}
        {view === "new" && (
          <NewReviewForm form={newForm} setForm={setNewForm} onCreate={createEngagement} />
        )}

        {/* ── LIST VIEW ── */}
        {view === "list" && (
          <ListView
            engagements={engagements}
            onOpen={(id) => { setActiveId(id); setView("active") }}
            onDelete={deleteEngagement}
            onNew={() => setView("new")}
          />
        )}

        {/* ── ACTIVE CHECKLIST ── */}
        {view === "active" && active && (
          <ActiveChecklist
            engagement={active}
            onSetResult={setCheckResult}
            onSetNotes={setCheckNotes}
            onUpdateField={updateEngagementField}
          />
        )}
      </div>

      {/* ── REPORT MODAL ── */}
      {showExport && active && (
        <ExportModal
          engagement={active}
          onClose={() => setShowExport(false)}
        />
      )}
    </div>
  )
}

// ── NEW REVIEW FORM ────────────────────────────────────────────────────────
function NewReviewForm({ form, setForm, onCreate }) {
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))
  const PACKAGES = ["Starter Snapshot — $250", "Business Snapshot — $500", "Remediation Support — $1,000+"]
  const LICENSES = ["Microsoft 365 Business Basic", "Microsoft 365 Business Standard", "Microsoft 365 Business Premium", "Mixed / Not sure"]
  return (
    <div className="max-w-lg mx-auto">
      <div className="mb-6">
        <p className="text-[11px] font-mono text-[#60a5fa] uppercase tracking-wider mb-1">New Security Review</p>
        <p className="text-[22px] font-semibold text-[#e8f0fe]">Start a Checklist</p>
        <p className="text-[13px] text-[#7a9abf] mt-1">Timer starts automatically when you begin.</p>
      </div>
      <div className="bg-[#0d1520] border border-[#1a2d45] rounded-xl p-5 space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Contact Name *</label>
            <input value={form.clientName} onChange={e => set("clientName", e.target.value)}
              placeholder="Jane Smith"
              className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors" />
          </div>
          <div>
            <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Company *</label>
            <input value={form.company} onChange={e => set("company", e.target.value)}
              placeholder="Acme Dental"
              className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors" />
          </div>
        </div>
        <div>
          <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Package</label>
          <select value={form.package} onChange={e => set("package", e.target.value)}
            className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] focus:outline-none focus:border-[#3b82f6] transition-colors">
            {PACKAGES.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">License Type</label>
            <select value={form.licenseType} onChange={e => set("licenseType", e.target.value)}
              className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] focus:outline-none focus:border-[#3b82f6] transition-colors">
              <option value="">— Select —</option>
              {LICENSES.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">User Count</label>
            <input value={form.userCount} onChange={e => set("userCount", e.target.value)}
              placeholder="e.g. 12"
              className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors" />
          </div>
        </div>
        <div>
          <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Pre-Review Notes</label>
          <textarea value={form.notes} onChange={e => set("notes", e.target.value)} rows={3}
            placeholder="Known concerns, context from discovery call, specific areas to focus on..."
            className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors resize-none" />
        </div>
        <button onClick={onCreate}
          className="w-full text-[14px] font-mono text-white bg-[#3b82f6] py-2.5 rounded-lg hover:bg-[#2563eb] transition-colors">
          Start Review →
        </button>
      </div>
    </div>
  )
}

// ── LIST VIEW ──────────────────────────────────────────────────────────────
function ListView({ engagements, onOpen, onDelete, onNew }) {
  if (engagements.length === 0) return (
    <div className="text-center py-20">
      <div className="w-14 h-14 rounded-xl bg-[#0d1520] border border-[#1a2d45] flex items-center justify-center mx-auto mb-4">
        <svg viewBox="0 0 24 24" fill="none" className="w-7 h-7">
          <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2" stroke="#3b82f6" strokeWidth="1.5" strokeLinecap="round"/>
          <rect x="9" y="3" width="6" height="4" rx="1" stroke="#3b82f6" strokeWidth="1.5"/>
          <path d="M9 12h6M9 16h4" stroke="#60a5fa" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
      </div>
      <p className="text-[15px] font-semibold text-[#e8f0fe] mb-1">No reviews yet</p>
      <p className="text-[13px] text-[#7a9abf] mb-5">Start a new review to run your first M365 security checklist.</p>
      <button onClick={onNew} className="text-[13px] font-mono text-white bg-[#3b82f6] px-5 py-2 rounded-lg hover:bg-[#2563eb] transition-colors">+ New Review</button>
    </div>
  )
  return (
    <div className="space-y-3">
      <p className="text-[11px] font-mono text-[#3d5a7a] uppercase tracking-wider mb-4">{engagements.length} review{engagements.length !== 1 ? "s" : ""}</p>
      {engagements.map(eng => {
        const pct = calcProgress(eng.checks)
        const { pass, fail } = calcScore(eng.checks)
        const isDone = pct === 100
        return (
          <div key={eng.id} onClick={() => onOpen(eng.id)}
            className={`bg-[#0d1520] border rounded-xl p-4 cursor-pointer hover:bg-[#111d2e] transition-all ${isDone ? "border-green-500/30" : "border-[#1a2d45] hover:border-[#1e3a5f]"}`}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <p className="text-[14px] font-semibold text-[#e8f0fe] truncate">{eng.company}</p>
                <p className="text-[11px] text-[#7a9abf]">{eng.clientName} · {formatDate(eng.createdAt)}</p>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                {eng.duration > 0 && <span className="text-[11px] font-mono text-[#3d5a7a]">{formatDuration(eng.duration)}</span>}
                <div className="text-right">
                  <p className={`text-[13px] font-mono font-semibold ${isDone ? "text-green-400" : "text-[#60a5fa]"}`}>{pct}%</p>
                  {(pass > 0 || fail > 0) && <p className="text-[10px] font-mono text-[#3d5a7a]">{pass}✓ {fail}✗</p>}
                </div>
                <button onClick={e => { e.stopPropagation(); if (window.confirm("Delete this review?")) onDelete(eng.id) }}
                  className="text-[#3d5a7a] hover:text-red-400 transition-colors text-[11px] font-mono px-1.5 py-0.5 rounded border border-transparent hover:border-red-500/20">
                  ✕
                </button>
              </div>
            </div>
            <div className="mt-3">
              <div className="h-1 bg-[#1a2d45] rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all ${isDone ? "bg-green-500" : "bg-gradient-to-r from-[#3b82f6] to-[#60a5fa]"}`} style={{ width: `${pct}%` }} />
              </div>
            </div>
            <p className="text-[11px] font-mono text-[#3d5a7a] mt-2 truncate">{eng.package}</p>
          </div>
        )
      })}
    </div>
  )
}

// ── ACTIVE CHECKLIST ───────────────────────────────────────────────────────
function ActiveChecklist({ engagement, onSetResult, onSetNotes, onUpdateField }) {
  const [expandedSection, setExpandedSection] = useState(SECTIONS[0].id)
  const [editingNote, setEditingNote] = useState(null)
  const [noteText, setNoteText] = useState("")
  const pct = calcProgress(engagement.checks)
  const { pass, fail } = calcScore(engagement.checks)
  const totalChecks = SECTIONS.reduce((n, s) => n + s.checks.length, 0)
  const doneChecks = Object.values(engagement.checks || {}).filter(v => v.result).length

  return (
    <div className="max-w-3xl mx-auto">
      {/* Client info bar */}
      <div className="bg-[#0d1520] border border-[#1a2d45] rounded-xl p-4 mb-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <p className="text-[16px] font-semibold text-[#e8f0fe]">{engagement.company}</p>
            <p className="text-[12px] text-[#7a9abf]">{engagement.clientName} · {engagement.package}</p>
            {engagement.licenseType && <p className="text-[11px] font-mono text-[#3d5a7a] mt-0.5">{engagement.licenseType}{engagement.userCount ? ` · ${engagement.userCount} users` : ""}</p>}
          </div>
          <div className="flex items-center gap-4">
            <div className="text-center"><p className="text-[18px] font-semibold text-green-400">{pass}</p><p className="text-[10px] font-mono text-[#3d5a7a] uppercase">Pass</p></div>
            <div className="text-center"><p className="text-[18px] font-semibold text-red-400">{fail}</p><p className="text-[10px] font-mono text-[#3d5a7a] uppercase">Fail</p></div>
            <div className="text-center"><p className="text-[18px] font-semibold text-[#60a5fa]">{pct}%</p><p className="text-[10px] font-mono text-[#3d5a7a] uppercase">{doneChecks}/{totalChecks}</p></div>
          </div>
        </div>
        <div className="mt-3 h-1.5 bg-[#1a2d45] rounded-full overflow-hidden">
          <div className="h-full bg-gradient-to-r from-[#3b82f6] to-[#60a5fa] rounded-full transition-all duration-300" style={{ width: `${pct}%` }} />
        </div>
      </div>

      {/* Sections */}
      {SECTIONS.map(section => {
        const sectionChecks = section.checks
        const sectionDone = sectionChecks.filter(c => engagement.checks?.[c.id]?.result).length
        const sectionFail = sectionChecks.filter(c => engagement.checks?.[c.id]?.result === "fail").length
        const isOpen = expandedSection === section.id
        const sevMeta = SEVERITY_META[section.severity]

        return (
          <div key={section.id} className={`mb-3 rounded-xl border overflow-hidden transition-all ${isOpen ? "border-[#1e3a5f]" : "border-[#1a2d45]"}`}>
            {/* Section header */}
            <div onClick={() => setExpandedSection(isOpen ? null : section.id)}
              className={`flex items-center gap-3 px-4 py-3 cursor-pointer transition-colors ${isOpen ? "bg-[#111d2e]" : "bg-[#0d1520] hover:bg-[#0d1520]/80"}`}>
              <span className="text-[16px]">{section.icon}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <p className="text-[13px] font-semibold text-[#e8f0fe]">{section.label}</p>
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${sevMeta.bg} ${sevMeta.color} ${sevMeta.border}`}>{sevMeta.label}</span>
                  {sectionFail > 0 && <span className="text-[10px] font-mono text-red-400 border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 rounded">{sectionFail} fail</span>}
                </div>
                <p className="text-[11px] text-[#3d5a7a] mt-0.5 hidden sm:block">{section.desc}</p>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <span className="text-[11px] font-mono text-[#3d5a7a]">{sectionDone}/{sectionChecks.length}</span>
                <span className={`text-[#3d5a7a] transition-transform duration-200 ${isOpen ? "rotate-180" : ""}`}>▾</span>
              </div>
            </div>

            {/* Checks */}
            {isOpen && (
              <div className="bg-[#0d1520] divide-y divide-[#1a2d45]/50">
                {sectionChecks.map(check => {
                  const checkData = engagement.checks?.[check.id] || {}
                  const result = checkData.result
                  const notes = checkData.notes || ""
                  const isEditingThisNote = editingNote === check.id
                  const cSev = SEVERITY_META[check.severity]

                  return (
                    <div key={check.id} className={`px-4 py-3 transition-colors ${result === "fail" ? "bg-red-500/5" : result === "pass" ? "bg-green-500/3" : ""}`}>
                      <div className="flex items-start gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${cSev.bg} ${cSev.color} ${cSev.border}`}>{cSev.label}</span>
                            <p className="text-[13px] text-[#e8f0fe] leading-snug">{check.label}</p>
                          </div>
                          <p className="text-[11px] text-[#3d5a7a] leading-relaxed">{check.note}</p>
                          {notes && !isEditingThisNote && (
                            <p className="text-[11px] text-[#7a9abf] mt-1 italic">"{notes}"</p>
                          )}
                          {isEditingThisNote && (
                            <div className="flex gap-2 mt-2">
                              <input value={noteText} onChange={e => setNoteText(e.target.value)} placeholder="Add notes..."
                                autoFocus
                                className="flex-1 bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-1.5 text-[12px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors"
                                onKeyDown={e => {
                                  if (e.key === "Enter") { onSetNotes(check.id, noteText); setEditingNote(null) }
                                  if (e.key === "Escape") setEditingNote(null)
                                }} />
                              <button onClick={() => { onSetNotes(check.id, noteText); setEditingNote(null) }}
                                className="text-[11px] font-mono text-white bg-[#3b82f6] px-3 py-1.5 rounded-lg hover:bg-[#2563eb] transition-colors">Save</button>
                              <button onClick={() => setEditingNote(null)}
                                className="text-[11px] font-mono text-[#7a9abf] border border-[#1a2d45] px-2 py-1.5 rounded-lg">✕</button>
                            </div>
                          )}
                        </div>

                        {/* Result buttons + note toggle */}
                        <div className="flex items-center gap-1.5 flex-shrink-0">
                          <button onClick={() => { setEditingNote(check.id); setNoteText(notes) }}
                            className="text-[#3d5a7a] hover:text-[#60a5fa] text-[10px] font-mono border border-transparent hover:border-[#1e3a5f] px-1.5 py-1 rounded transition-colors">
                            {notes ? "📝" : "+ note"}
                          </button>
                          {["pass", "fail", "na"].map(r => {
                            const rm = RESULT_META[r]
                            const isActive = result === r
                            return (
                              <button key={r} onClick={() => onSetResult(check.id, isActive ? null : r)}
                                className={`text-[10px] font-mono px-2 py-1 rounded border transition-all ${isActive ? `${rm.bg} ${rm.color} ${rm.border}` : "text-[#3d5a7a] border-[#1a2d45] hover:border-[#1e3a5f] hover:text-[#7a9abf]"}`}>
                                {rm.label}
                              </button>
                            )
                          })}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}

      {/* Secure Score notepad */}
      <div className="mt-5 bg-[#0d1520] border border-[#1a2d45] rounded-xl p-4">
        <p className="text-[11px] font-mono text-[#3d5a7a] uppercase tracking-wider mb-2">Microsoft Secure Score + Notes</p>
        <textarea
          defaultValue={engagement.secureScoreNotes || ""}
          onBlur={e => onUpdateField("secureScoreNotes", e.target.value)}
          rows={4}
          placeholder="Current Secure Score: ___/___&#10;Top recommended actions:&#10;1. &#10;2. &#10;3. &#10;&#10;Other observations..."
          className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[12px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors resize-none font-mono" />
      </div>
    </div>
  )
}

// ── REPORT MODAL ───────────────────────────────────────────────────────────
function ExportModal({ engagement, onClose }) {
  const [stage, setStage] = useState("ready") // ready | generating | done | error
  const [report, setReport] = useState(null)
  const [errorMsg, setErrorMsg] = useState("")

  const { pass, fail } = calcScore(engagement.checks)
  const total = pass + fail
  const pct = total ? Math.round((pass / total) * 100) : 0

  async function generateReport() {
    setStage("generating")
    setErrorMsg("")

    const failLines = []
    const passLines = []
    SECTIONS.forEach(section => {
      section.checks.forEach(check => {
        const r = engagement.checks?.[check.id]
        const sev = SEVERITY_META[check.severity]?.label || check.severity
        const notes = r?.notes ? ` (Notes: ${r.notes})` : ""
        if (r?.result === "fail") failLines.push(`[${sev}] ${check.label}${notes}`)
        if (r?.result === "pass") passLines.push(`[${sev}] ${check.label}`)
      })
    })

    const prompt = `You are writing a Microsoft 365 Security Snapshot report for a small business owner. The audience is non-technical.

CLIENT: ${engagement.company}${engagement.clientName ? ` (${engagement.clientName})` : ""}
PACKAGE: ${engagement.package || "Business Snapshot"}
REVIEW DATE: ${formatDate(engagement.createdAt)}
SCORE: ${pass} pass / ${fail} fail out of ${total} checks (${pct}%)
${engagement.licenseType ? `LICENSE: ${engagement.licenseType}` : ""}
${engagement.userCount ? `USERS: ${engagement.userCount}` : ""}
${engagement.secureScoreNotes ? `SECURE SCORE NOTES: ${engagement.secureScoreNotes}` : ""}

FAILED CHECKS (needs attention):
${failLines.join("\n") || "None"}

PASSING CHECKS (working well):
${passLines.join("\n") || "None"}

Respond with ONLY a valid JSON object (no markdown, no backticks):
{
  "executiveSummary": "2-3 sentences. Lead with what is working. Name the most critical risks plainly. End with the priority action. Define any technical term on first use.",
  "findings": [
    {
      "severity": "Critical|High|Medium",
      "title": "Short plain-English title — rewrite the checklist item, do not copy it verbatim",
      "explanation": "2-3 sentences. What this setting is, what could go wrong if it is not fixed, and why it matters to this specific business. No jargon. If a technical term is unavoidable, define it in parentheses."
    }
  ],
  "passItems": ["Short plain-English phrase describing what is working — rewrite, do not copy verbatim"]
}

Rules: findings = only FAILED checks, sorted Critical → High → Medium. passItems = only PASSING checks. Tone: calm, honest, reassuring. Never alarming or dismissive.`

    try {
      const res = await fetch("/api/generate-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-5",
          max_tokens: 1000,
          messages: [{ role: "user", content: prompt }]
        })
      })
      const data = await res.json()
      if (!res.ok) {
        const msg = data?.error || `Error ${res.status}`
        throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg))
      }
      const text = (data.content || []).map(b => b.text || "").join("")
      const clean = text.replace(/```json|```/g, "").trim()
      const parsed = JSON.parse(clean)
      setReport(parsed)
      setStage("done")
    } catch (e) {
      setErrorMsg(e.message || "Something went wrong. Try again.")
      setStage("error")
      console.error(e)
    }
  }

  function printReport() {
    const el = document.getElementById("ac-report-print-target")
    if (!el) return
    const w = window.open("", "_blank")
    w.document.write(`<!DOCTYPE html><html><head><title>M365 Security Snapshot — ${engagement.company}</title>
    <link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet"/>
    <style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{font-family:'DM Sans',sans-serif;font-size:14px;color:#111;background:#fff;padding:40px;max-width:760px;margin:0 auto}
      .r-masthead{border-bottom:1.5px solid #e5e7eb;padding-bottom:20px;margin-bottom:24px}
      .r-brandline{font-family:'DM Mono',monospace;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#6b7280;margin-bottom:6px}
      .r-title{font-family:'DM Serif Display',serif;font-size:26px;color:#111;line-height:1.1;margin-bottom:4px}
      .r-meta{font-size:12px;color:#6b7280;display:flex;gap:20px;flex-wrap:wrap;margin-top:8px}
      .r-meta span strong{color:#374151}
      .r-scores{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:24px}
      .r-score{background:#f9fafb;border-radius:8px;padding:12px;text-align:center;border:1px solid #f3f4f6}
      .r-score .n{font-family:'DM Serif Display',serif;font-size:28px;line-height:1}
      .r-score .l{font-size:11px;color:#9ca3af;margin-top:4px;font-family:'DM Mono',monospace;text-transform:uppercase;letter-spacing:.06em}
      .n.pass{color:#15803d}.n.fail{color:#b91c1c}.n.score{color:#1d4ed8}
      .r-exec{background:#fef9f2;border-left:3px solid #d97706;border-radius:0 8px 8px 0;padding:14px 18px;margin-bottom:24px;font-size:14px;color:#374151;line-height:1.7}
      .r-exec-lbl{font-family:'DM Mono',monospace;font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#d97706;margin-bottom:8px}
      .r-section{margin-bottom:20px}
      .r-section-title{font-family:'DM Serif Display',serif;font-size:16px;color:#111;border-bottom:1px solid #e5e7eb;padding-bottom:8px;margin-bottom:10px}
      .r-finding{display:flex;gap:10px;padding:9px 0;border-bottom:.5px solid #f3f4f6}
      .r-finding:last-child{border-bottom:none}
      .r-dot{width:7px;height:7px;border-radius:50%;background:#dc2626;margin-top:6px;flex-shrink:0}
      .r-badge{font-size:10px;font-family:'DM Mono',monospace;padding:2px 7px;border-radius:4px;white-space:nowrap;height:fit-content;margin-top:2px;flex-shrink:0}
      .rb-Critical{background:#fee2e2;color:#991b1b}.rb-High{background:#fef3c7;color:#92400e}.rb-Medium{background:#dbeafe;color:#1e40af}
      .r-finding-text strong{font-size:13px;font-weight:600;display:block;margin-bottom:3px}
      .r-finding-text p{font-size:12px;color:#4b5563;margin:0;line-height:1.6}
      .r-pass-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}
      .r-pass-item{display:flex;align-items:flex-start;gap:6px;font-size:12px;color:#374151;padding:6px 8px;background:#f0fdf4;border-radius:6px}
      .r-pass-dot{width:6px;height:6px;border-radius:50%;background:#16a34a;flex-shrink:0;margin-top:5px}
      .r-footer{margin-top:28px;padding-top:16px;border-top:1px solid #e5e7eb;display:flex;justify-content:space-between;font-size:11px;color:#9ca3af;flex-wrap:wrap;gap:4px}
    </style></head><body>${el.innerHTML}</body></html>`)
    w.document.close()
    setTimeout(() => w.print(), 400)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-4 px-3" style={{ background: "rgba(8,13,20,0.95)" }}>
      <div className="bg-[#0d1520] border border-[#1e3a5f] rounded-xl w-full max-w-2xl shadow-2xl overflow-y-auto" style={{ maxHeight: "96vh" }}>

        {/* Modal header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1a2d45]">
          <div>
            <p className="text-[11px] font-mono text-[#60a5fa] uppercase tracking-wider mb-0.5">Review Complete</p>
            <p className="text-[15px] font-semibold text-[#e8f0fe]">
              {stage === "done" ? "Security Snapshot Report" : "Generate Report"}
            </p>
          </div>
          <button onClick={onClose} className="text-[#7a9abf] hover:text-[#e8f0fe] text-xl px-1">×</button>
        </div>

        <div className="p-5">

          {/* Score summary — always visible */}
          <div className="bg-[#080d14] border border-[#1a2d45] rounded-xl p-4 mb-5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-[13px] font-semibold text-[#e8f0fe]">{engagement.company}</p>
                <p className="text-[11px] text-[#7a9abf]">{formatDate(engagement.createdAt)} · {formatDuration(engagement.duration || 0)}</p>
              </div>
              <div className="flex items-center gap-4">
                <div className="text-center"><p className="text-[18px] font-semibold text-green-400">{pass}</p><p className="text-[10px] font-mono text-[#3d5a7a]">PASS</p></div>
                <div className="text-center"><p className="text-[18px] font-semibold text-red-400">{fail}</p><p className="text-[10px] font-mono text-[#3d5a7a]">FAIL</p></div>
                <div className="text-center"><p className="text-[18px] font-semibold text-[#60a5fa]">{pct}%</p><p className="text-[10px] font-mono text-[#3d5a7a]">SCORE</p></div>
              </div>
            </div>
          </div>

          {/* READY state */}
          {stage === "ready" && (
            <>
              <div className="bg-[#111d2e] border border-[#1a2d45] rounded-xl p-4 mb-5">
                <p className="text-[12px] font-semibold text-[#e8f0fe] mb-1">What happens next</p>
                <p className="text-[12px] text-[#7a9abf] leading-relaxed">Claude will read your findings and write a plain-English report — executive summary, prioritized findings with explanations, and what's working well. Ready to print or send in under 30 seconds.</p>
              </div>
              <button onClick={generateReport}
                className="w-full text-[14px] font-mono text-white bg-[#3b82f6] py-3 rounded-xl hover:bg-[#2563eb] transition-colors">
                Generate Plain-English Report →
              </button>
            </>
          )}

          {/* GENERATING state */}
          {stage === "generating" && (
            <div className="flex flex-col items-center justify-center py-12 gap-4">
              <div className="w-8 h-8 border-2 border-[#1e3a5f] border-t-[#60a5fa] rounded-full animate-spin" />
              <p className="text-[13px] font-mono text-[#60a5fa]">Writing report for {engagement.company}…</p>
              <p className="text-[11px] text-[#3d5a7a]">This takes about 10–15 seconds</p>
            </div>
          )}

          {/* ERROR state */}
          {stage === "error" && (
            <>
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 mb-4">
                <p className="text-[12px] text-red-400">{errorMsg}</p>
              </div>
              <button onClick={generateReport}
                className="w-full text-[14px] font-mono text-white bg-[#3b82f6] py-3 rounded-xl hover:bg-[#2563eb] transition-colors">
                Try Again
              </button>
            </>
          )}

          {/* DONE state — rendered report */}
          {stage === "done" && report && (
            <>
              <div className="flex gap-2 mb-4">
                <button onClick={printReport}
                  className="flex-1 text-[12px] font-mono text-white bg-green-600 py-2 rounded-lg hover:bg-green-700 transition-colors">
                  Print / Save PDF
                </button>
                <button onClick={() => setStage("ready")}
                  className="text-[12px] font-mono text-[#7a9abf] border border-[#1a2d45] px-4 py-2 rounded-lg hover:text-[#e8f0fe] hover:border-[#1e3a5f] transition-colors">
                  Regenerate
                </button>
              </div>

              {/* White report card */}
              <div id="ac-report-print-target" style={{
                background: "#fff", borderRadius: 12, padding: "32px 36px",
                color: "#111", fontFamily: "'DM Sans', sans-serif", lineHeight: 1.6
              }}>
                {/* Masthead */}
                <div style={{ borderBottom: "1.5px solid #e5e7eb", paddingBottom: 18, marginBottom: 20 }}>
                  <p style={{ fontFamily: "monospace", fontSize: 11, letterSpacing: "0.1em", textTransform: "uppercase", color: "#6b7280", marginBottom: 6 }}>Amazin Cyber Solutions — Confidential</p>
                  <p style={{ fontSize: 24, fontWeight: 600, color: "#111", marginBottom: 4 }}>Microsoft 365 Security Snapshot</p>
                  <div style={{ fontSize: 12, color: "#6b7280", display: "flex", gap: 20, flexWrap: "wrap", marginTop: 6 }}>
                    <span>Prepared for: <strong style={{ color: "#374151" }}>{engagement.clientName ? `${engagement.clientName}, ` : ""}{engagement.company}</strong></span>
                    <span>Package: <strong style={{ color: "#374151" }}>{engagement.package}</strong></span>
                    <span>Reviewed: <strong style={{ color: "#374151" }}>{formatDate(engagement.createdAt)}</strong></span>
                    {engagement.duration > 0 && <span>Duration: <strong style={{ color: "#374151" }}>{formatDuration(engagement.duration)}</strong></span>}
                  </div>
                </div>

                {/* Score row */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10, marginBottom: 22 }}>
                  {[["PASSING", pass, "#15803d"], ["NEEDS ATTENTION", fail, "#b91c1c"], ["OVERALL SCORE", `${pct}%`, "#1d4ed8"]].map(([lbl, val, col]) => (
                    <div key={lbl} style={{ background: "#f9fafb", borderRadius: 8, padding: "12px 14px", textAlign: "center", border: "1px solid #f3f4f6" }}>
                      <div style={{ fontSize: 26, fontWeight: 600, color: col, lineHeight: 1 }}>{val}</div>
                      <div style={{ fontSize: 10, color: "#9ca3af", marginTop: 4, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.06em" }}>{lbl}</div>
                    </div>
                  ))}
                </div>

                {/* Executive summary */}
                <div style={{ background: "#fef9f2", borderLeft: "3px solid #d97706", borderRadius: "0 8px 8px 0", padding: "12px 16px", marginBottom: 22 }}>
                  <p style={{ fontFamily: "monospace", fontSize: 10, textTransform: "uppercase", letterSpacing: "0.1em", color: "#d97706", marginBottom: 8 }}>Executive Summary</p>
                  <p style={{ fontSize: 14, color: "#374151", lineHeight: 1.7, margin: 0 }}>{report.executiveSummary}</p>
                </div>

                {/* Findings */}
                {report.findings?.length > 0 && (
                  <div style={{ marginBottom: 20 }}>
                    <p style={{ fontSize: 16, fontWeight: 600, color: "#111", borderBottom: "1px solid #e5e7eb", paddingBottom: 8, marginBottom: 10 }}>Findings — What Needs Attention</p>
                    {report.findings.map((f, i) => (
                      <div key={i} style={{ display: "flex", gap: 10, padding: "9px 0", borderBottom: i < report.findings.length - 1 ? "0.5px solid #f3f4f6" : "none" }}>
                        <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#dc2626", marginTop: 6, flexShrink: 0 }} />
                        <div>
                          <span style={{ fontSize: 10, fontFamily: "monospace", padding: "2px 7px", borderRadius: 4,
                            background: f.severity === "Critical" ? "#fee2e2" : f.severity === "High" ? "#fef3c7" : "#dbeafe",
                            color: f.severity === "Critical" ? "#991b1b" : f.severity === "High" ? "#92400e" : "#1e40af",
                            marginRight: 8 }}>{f.severity}</span>
                          <strong style={{ fontSize: 13, fontWeight: 600 }}>{f.title}</strong>
                          <p style={{ fontSize: 12, color: "#4b5563", marginTop: 3, lineHeight: 1.6 }}>{f.explanation}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Pass items */}
                {report.passItems?.length > 0 && (
                  <div style={{ marginBottom: 20 }}>
                    <p style={{ fontSize: 16, fontWeight: 600, color: "#111", borderBottom: "1px solid #e5e7eb", paddingBottom: 8, marginBottom: 10 }}>What's Working Well</p>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                      {report.passItems.map((p, i) => (
                        <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 6, fontSize: 12, color: "#374151", padding: "6px 8px", background: "#f0fdf4", borderRadius: 6, border: "1px solid #dcfce7" }}>
                          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#16a34a", flexShrink: 0, marginTop: 5 }} />
                          <span>{p}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Footer */}
                <div style={{ marginTop: 24, paddingTop: 14, borderTop: "1px solid #e5e7eb", display: "flex", justifyContent: "space-between", fontSize: 11, color: "#9ca3af", flexWrap: "wrap", gap: 4 }}>
                  <span>Prepared by Oshé · Amazin Cyber Solutions · amazincyber.com</span>
                  <span>Confidential — for {engagement.company} only</span>
                </div>
              </div>
            </>
          )}

        </div>
      </div>
    </div>
  )
}
