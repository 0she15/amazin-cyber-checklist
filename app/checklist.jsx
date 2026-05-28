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

// ── EXPORT BUILDER ─────────────────────────────────────────────────────────
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

  lines.push(`── CLAUDE REPORT PROMPT ──`)
  lines.push(`Use the findings above to generate a plain-English Microsoft 365 Security Snapshot report for ${engagement.company || "this client"}.`)
  lines.push(``)
  lines.push(`Instructions:`)
  lines.push(`- Write an Executive Summary of 2-3 sentences a business owner can understand`)
  lines.push(`- Summarize findings by section (MFA, Admin Roles, Email Security, Conditional Access, Mailbox Rules)`)
  lines.push(`- List Critical findings first, then High, then Medium`)
  lines.push(`- For each finding, explain what it means in plain English and why it matters to the business`)
  lines.push(`- End with a "What's Working Well" section for all Pass items`)
  lines.push(`- Tone: calm, clear, no jargon. Write for a business owner, not an IT team.`)
  lines.push(`- Do not use acronyms without explaining them on first use`)

  return lines.join("\n")
}

export default function Checklist() {
  const [engagements, setEngagements] = useState([])
  const [loaded, setLoaded] = useState(false)
  const [view, setView] = useState("list") // list | active | new
  const [activeId, setActiveId] = useState(null)
  const [showExport, setShowExport] = useState(false)
  const [exportCopied, setExportCopied] = useState(false)
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
                  Export Findings
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

      {/* ── EXPORT MODAL ── */}
      {showExport && active && (
        <ExportModal
          engagement={active}
          onClose={() => { setShowExport(false); setExportCopied(false) }}
          copied={exportCopied}
          onCopy={() => {
            navigator.clipboard.writeText(buildExport(active))
            setExportCopied(true)
          }}
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

// ── EXPORT MODAL ───────────────────────────────────────────────────────────
function ExportModal({ engagement, onClose, copied, onCopy }) {
  const text = buildExport(engagement)
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-4 px-3" style={{ background: "rgba(8,13,20,0.95)" }}>
      <div className="bg-[#0d1520] border border-[#1e3a5f] rounded-xl w-full max-w-2xl shadow-2xl overflow-y-auto" style={{ maxHeight: "96vh" }}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1a2d45]">
          <div>
            <p className="text-[11px] font-mono text-[#60a5fa] uppercase tracking-wider mb-0.5">Review Complete</p>
            <p className="text-[15px] font-semibold text-[#e8f0fe]">Export Findings</p>
          </div>
          <button onClick={onClose} className="text-[#7a9abf] hover:text-[#e8f0fe] text-xl px-1">×</button>
        </div>

        <div className="p-5">
          <div className="bg-[#080d14] border border-[#1a2d45] rounded-xl p-4 mb-4">
            <div className="flex items-start justify-between gap-3 mb-3">
              <div>
                <p className="text-[13px] font-semibold text-[#e8f0fe]">{engagement.company}</p>
                <p className="text-[11px] text-[#7a9abf]">{formatDate(engagement.createdAt)} · {formatDuration(engagement.duration || 0)}</p>
              </div>
              <div className="flex items-center gap-3">
                {(() => { const { pass, fail } = calcScore(engagement.checks); return (
                  <>
                    <div className="text-center"><p className="text-[16px] font-semibold text-green-400">{pass}</p><p className="text-[10px] font-mono text-[#3d5a7a]">PASS</p></div>
                    <div className="text-center"><p className="text-[16px] font-semibold text-red-400">{fail}</p><p className="text-[10px] font-mono text-[#3d5a7a]">FAIL</p></div>
                  </>
                )})()}
              </div>
            </div>
          </div>

          <div className="bg-[#080d14] border border-[#1a2d45] rounded-xl p-4 mb-4 max-h-64 overflow-y-auto">
            <pre className="text-[11px] font-mono text-[#7a9abf] whitespace-pre-wrap leading-relaxed">{text}</pre>
          </div>

          <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 mb-4">
            <p className="text-[12px] font-semibold text-[#60a5fa] mb-1">Next step</p>
            <p className="text-[12px] text-[#7a9abf] leading-relaxed">Copy this output and paste it into Claude with the message: <span className="text-[#e8f0fe] font-mono">"Generate a plain-English M365 security report from these findings."</span> Edit the draft, export as PDF, send to client.</p>
          </div>

          <button onClick={onCopy}
            className={`w-full text-[14px] font-mono py-3 rounded-xl border transition-all ${copied ? "text-green-400 border-green-500/40 bg-green-500/10" : "text-white bg-[#3b82f6] border-transparent hover:bg-[#2563eb]"}`}>
            {copied ? "✓ Copied to clipboard — paste into Claude" : "Copy to Clipboard"}
          </button>
        </div>
      </div>
    </div>
  )
}
