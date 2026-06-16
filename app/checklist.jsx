"use client"
import { useState, useEffect, useRef } from "react"

const STORAGE_KEY = "amazin_checklists"
const AUTH_STORAGE_KEY = "amazin_supabase_session"
const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || ""
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || ""
const SUPABASE_CONFIGURED = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY)

function supabaseHeaders(session, extra = {}) {
  return {
    apikey: SUPABASE_ANON_KEY,
    Authorization: `Bearer ${session?.access_token || SUPABASE_ANON_KEY}`,
    ...extra,
  }
}

async function supabaseRequest(path, { method = "GET", body, session, headers = {} } = {}) {
  if (!SUPABASE_CONFIGURED) throw new Error("Supabase environment variables are not configured.")
  const res = await fetch(`${SUPABASE_URL}${path}`, {
    method,
    headers: supabaseHeaders(session, {
      "Content-Type": "application/json",
      ...headers,
    }),
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) throw new Error(data?.message || data?.error_description || data?.error || `Supabase error ${res.status}`)
  return data
}

async function authRequest(path, body) {
  if (!SUPABASE_CONFIGURED) throw new Error("Supabase environment variables are not configured.")
  const res = await fetch(`${SUPABASE_URL}${path}`, {
    method: "POST",
    headers: {
      apikey: SUPABASE_ANON_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data?.msg || data?.message || data?.error_description || data?.error || `Auth error ${res.status}`)
  return data
}

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
  {
    id: "sharing",
    label: "Data Sharing + Collaboration",
    severity: "high",
    icon: "🔗",
    desc: "Small businesses leak more data through sharing than hacking.",
    checks: [
      { id: "anon_links",    label: "Anonymous sharing links disabled or restricted",       severity: "high",     note: "SharePoint admin → Sharing → 'Anyone' links should be disabled" },
      { id: "ext_sharing",   label: "External sharing restricted to specific domains",      severity: "high",     note: "Default allows sharing with anyone — should be scoped to known partners" },
      { id: "guest_users",   label: "Guest users reviewed — only active, known accounts",  severity: "high",     note: "Entra ID → External Identities → list and review all guest accounts" },
      { id: "stale_guests",  label: "No stale guest accounts (inactive 90+ days)",         severity: "medium",   note: "Former contractors and vendor contacts often left with active access" },
      { id: "sensitive_sites", label: "Sensitive SharePoint sites have restricted access", severity: "medium",   note: "HR, finance, and executive sites should have explicit access controls" },
      { id: "onedrive_sharing", label: "OneDrive default sharing set to internal only",    severity: "medium",   note: "Admin center → SharePoint → Settings → Default sharing scope" },
    ],
  },
  {
    id: "endpoint",
    label: "Endpoint Security",
    severity: "high",
    icon: "💻",
    desc: "Devices are the front door. Requires Business Premium or Intune licensing.",
    checks: [
      { id: "intune_enrolled", label: "Devices enrolled in Microsoft Intune",              severity: "high",     note: "N/A if Business Basic/Standard — requires Business Premium or Intune add-on" },
      { id: "compliance_policy", label: "Device compliance policies configured",           severity: "high",     note: "Intune → Device compliance → Policies — should require encryption + PIN" },
      { id: "defender_active", label: "Microsoft Defender antivirus active on all devices", severity: "critical", note: "Check Intune or Defender portal for devices with protection disabled" },
      { id: "bitlocker",     label: "BitLocker (disk encryption) enabled on Windows devices", severity: "high",  note: "Required for compliance — lost laptops with unencrypted drives are reportable incidents" },
      { id: "local_admin",   label: "Local administrator rights reviewed and restricted",  severity: "medium",   note: "Users should not have local admin rights on managed devices" },
    ],
  },
  {
    id: "continuity",
    label: "Backup + Recovery",
    severity: "high",
    icon: "🔄",
    desc: "Microsoft does not back up your data. This surprises almost every SMB client.",
    checks: [
      { id: "m365_backup",   label: "Third-party M365 backup solution in place",           severity: "critical", note: "Microsoft's retention ≠ backup. Deleted data is gone after retention window." },
      { id: "breakglass",    label: "Break-glass emergency admin account exists",          severity: "high",     note: "Cloud-only account not tied to any person — locked in a vault for emergencies" },
      { id: "security_contact", label: "Security alert contacts configured in M365",       severity: "medium",   note: "Admin center → Settings → Org settings → Security contact — should be current" },
      { id: "ir_contact",    label: "Incident response contact documented",                severity: "medium",   note: "Who do they call if something goes wrong at 2am? Should be documented somewhere." },
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
function todayISODate() { return new Date().toISOString().slice(0, 10) }
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

// Letter grade — weighted: critical failures penalize more than medium
function calcGrade(checks) {
  let weightedPass = 0, weightedTotal = 0
  const weights = { critical: 3, high: 2, medium: 1 }
  SECTIONS.forEach(s => s.checks.forEach(c => {
    const r = checks?.[c.id]?.result
    const w = weights[c.severity] || 1
    if (r === "pass" || r === "fail") {
      weightedTotal += w
      if (r === "pass") weightedPass += w
    }
  }))
  if (weightedTotal === 0) return null
  const pct = (weightedPass / weightedTotal) * 100
  if (pct >= 93) return { grade: "A",  plus: false, color: "#15803d", bg: "#f0fdf4", border: "#86efac" }
  if (pct >= 90) return { grade: "A",  plus: false, minus: true, color: "#15803d", bg: "#f0fdf4", border: "#86efac" }
  if (pct >= 87) return { grade: "B",  plus: true,  color: "#1d4ed8", bg: "#eff6ff", border: "#93c5fd" }
  if (pct >= 83) return { grade: "B",  plus: false, color: "#1d4ed8", bg: "#eff6ff", border: "#93c5fd" }
  if (pct >= 80) return { grade: "B",  plus: false, minus: true, color: "#1d4ed8", bg: "#eff6ff", border: "#93c5fd" }
  if (pct >= 77) return { grade: "C",  plus: true,  color: "#d97706", bg: "#fffbeb", border: "#fcd34d" }
  if (pct >= 73) return { grade: "C",  plus: false, color: "#d97706", bg: "#fffbeb", border: "#fcd34d" }
  if (pct >= 70) return { grade: "C",  plus: false, minus: true, color: "#d97706", bg: "#fffbeb", border: "#fcd34d" }
  if (pct >= 60) return { grade: "D",  plus: false, color: "#ea580c", bg: "#fff7ed", border: "#fdba74" }
  return           { grade: "F",  plus: false, color: "#dc2626", bg: "#fef2f2", border: "#fca5a5" }
}

function getChecklistStats(checks) {
  const totalChecks = SECTIONS.reduce((n, s) => n + s.checks.length, 0)
  const completedCount = Object.values(checks || {}).filter(v => v.result).length
  const completionPct = Math.round((completedCount / totalChecks) * 100)
  return { totalChecks, completedCount, completionPct }
}

function getReportQualityIssues(engagement) {
  const { completedCount, completionPct } = getChecklistStats(engagement.checks)
  const issues = []
  if (!engagement.reviewerName?.trim()) issues.push("Assessor name is required.")
  if (!engagement.reviewDate?.trim()) issues.push("Assessment date is required.")
  if (!engagement.scope?.trim()) issues.push("Assessment scope is required.")
  if (completionPct < 60) issues.push("At least 60% of checklist items must be completed.")
  if (completedCount < 20) issues.push("Complete at least 20 checklist items before generating a client report.")
  return issues
}

function buildStructuredReportPayload(engagement) {
  const { pass, fail } = calcScore(engagement.checks)
  const { totalChecks, completedCount, completionPct } = getChecklistStats(engagement.checks)
  const total = pass + fail
  const pct = total ? Math.round((pass / total) * 100) : 0
  const grade = calcGrade(engagement.checks)
  const gradeSuffix = grade ? (grade.plus ? "+" : grade.minus ? "−" : "") : ""
  const gradeLabel = grade ? `${grade.grade}${gradeSuffix}` : "Not calculated"
  const failed = []
  const passing = []
  const notApplicable = []

  SECTIONS.forEach(section => {
    section.checks.forEach(check => {
      const r = engagement.checks?.[check.id]
      const item = {
        id: check.id,
        section: section.label,
        label: check.label,
        severity: SEVERITY_META[check.severity]?.label || check.severity,
        notes: r?.notes || "",
      }
      if (r?.result === "fail") failed.push(item)
      if (r?.result === "pass") passing.push(item)
      if (r?.result === "na") notApplicable.push(item)
    })
  })

  return {
    client: {
      company: engagement.company || "",
      clientName: engagement.clientName || "",
      package: engagement.package || "Business Security Assessment",
      licenseType: engagement.licenseType || "",
      userCount: engagement.userCount || "",
      reviewerName: engagement.reviewerName || "",
      reviewDate: engagement.reviewDate || "",
      scope: engagement.scope || "",
      secureScoreNotes: engagement.secureScoreNotes || "",
    },
    score: { pass, fail, total, pct, grade: gradeLabel, completionPct, completedCount, totalChecks },
    checks: { failed, passing, notApplicable },
  }
}

// Canonical package labels — must match the proposal generator's PACKAGES
// options exactly so a one-click prefill (?package=) selects the right option.
const PROPOSAL_PACKAGES = [
  "Security Snapshot Assessment — $750",
  "Business Security Assessment — $1,500",
  "Security Remediation — Starting at $2,500",
  "Ongoing Security Monitoring — Starting at $299/month",
]

// Map any stored package label (new or legacy) to a canonical proposal package
// so older assessments still prefill the proposal generator correctly.
function proposalPackageFor(pkg) {
  const s = (pkg || "").toLowerCase()
  if (s.includes("monitoring") || s.includes("299")) return PROPOSAL_PACKAGES[3]
  if (s.includes("remediation") || s.includes("2,500") || s.includes("2500") || s.includes("1,000") || s.includes("1000")) return PROPOSAL_PACKAGES[2]
  if (s.includes("business") || s.includes("1,500") || s.includes("1500") || s.includes("500")) return PROPOSAL_PACKAGES[1]
  if (s.includes("snapshot") || s.includes("starter") || s.includes("750") || s.includes("250")) return PROPOSAL_PACKAGES[0]
  return PROPOSAL_PACKAGES[1]
}

function buildProposalSummary(engagement, pass, fail, pct) {
  const fails = []
  SECTIONS.forEach(s => s.checks.forEach(c => {
    if (engagement.checks?.[c.id]?.result === "fail") fails.push(c.label)
  }))
  return [
    `Security Snapshot completed ${formatDate(engagement.createdAt)} for ${engagement.company}.`,
    `Score: ${pass} pass / ${fail} fail (${pct}%).`,
    `Suggested package: ${PROPOSAL_PACKAGES[2]}.`,
    fails.length ? `Key findings: ${fails.slice(0, 5).join("; ")}.` : "No failed checks were recorded.",
  ].join("\n")
}

function reviewFromRow(row) {
  const checks = {}
  ;(row.review_items || []).forEach(item => {
    checks[item.check_id] = { result: item.result || null, notes: item.notes || "" }
  })
  const client = Array.isArray(row.clients) ? row.clients[0] : row.clients
  return {
    id: row.id,
    clientId: row.client_id,
    clientName: client?.contact_name || "",
    company: client?.name || "Unknown company",
    package: row.package || "Business Security Assessment — $1,500",
    licenseType: row.license_type || "",
    userCount: row.user_count || "",
    reviewerName: row.reviewer_name || "",
    reviewDate: row.review_date || todayISODate(),
    scope: row.scope || "",
    notes: row.notes || "",
    secureScoreNotes: row.secure_score_notes || "",
    duration: row.duration_ms || 0,
    createdAt: row.created_at,
    completedAt: row.completed_at,
    checks,
  }
}

async function loadReviewsFromSupabase(session) {
  const select = "id,client_id,package,license_type,user_count,reviewer_name,review_date,scope,notes,secure_score_notes,duration_ms,created_at,completed_at,clients(id,name,contact_name),review_items(check_id,result,notes)"
  const rows = await supabaseRequest(`/rest/v1/reviews?select=${encodeURIComponent(select)}&order=created_at.desc`, { session })
  return (rows || []).map(reviewFromRow)
}

async function createReviewInSupabase(form, session) {
  const clients = await supabaseRequest("/rest/v1/clients?select=id,name,contact_name", {
    method: "POST",
    session,
    headers: { Prefer: "return=representation" },
    body: { name: form.company, contact_name: form.clientName },
  })
  const client = clients?.[0]
  if (!client?.id) throw new Error("Unable to create client record.")

  const reviews = await supabaseRequest("/rest/v1/reviews?select=id,client_id,package,license_type,user_count,reviewer_name,review_date,scope,notes,secure_score_notes,duration_ms,created_at,completed_at", {
    method: "POST",
    session,
    headers: { Prefer: "return=representation" },
    body: {
      client_id: client.id,
      package: form.package,
      license_type: form.licenseType || null,
      user_count: form.userCount || null,
      reviewer_name: form.reviewerName,
      review_date: form.reviewDate || todayISODate(),
      scope: form.scope,
      notes: form.notes || null,
      duration_ms: 0,
    },
  })
  const review = reviews?.[0]
  if (!review?.id) throw new Error("Unable to create assessment record.")
  return reviewFromRow({ ...review, clients: client, review_items: [] })
}

async function upsertReviewItem(session, reviewId, checkId, item) {
  await supabaseRequest("/rest/v1/review_items?on_conflict=review_id,check_id", {
    method: "POST",
    session,
    headers: { Prefer: "resolution=merge-duplicates" },
    body: {
      review_id: reviewId,
      check_id: checkId,
      result: item?.result || null,
      notes: item?.notes || null,
    },
  })
}

async function patchReview(session, reviewId, values) {
  await supabaseRequest(`/rest/v1/reviews?id=eq.${encodeURIComponent(reviewId)}`, {
    method: "PATCH",
    session,
    body: values,
  })
}

async function deleteReviewFromSupabase(session, reviewId) {
  await supabaseRequest(`/rest/v1/reviews?id=eq.${encodeURIComponent(reviewId)}`, {
    method: "DELETE",
    session,
  })
}

async function loadLatestGeneratedReport(session, reviewId) {
  const rows = await supabaseRequest(`/rest/v1/generated_reports?select=report,created_at&review_id=eq.${encodeURIComponent(reviewId)}&order=created_at.desc&limit=1`, { session })
  return rows?.[0]?.report || null
}

// ── EXPORT BUILDER (kept for reference / future use) ───────────────────────
function buildExport(engagement) {
  const lines = []
  lines.push(`AMAZIN CYBER — M365 SECURITY SNAPSHOT`)
  lines.push(`Client: ${engagement.clientName || "Unknown"}`)
  lines.push(`Company: ${engagement.company || "Unknown"}`)
  lines.push(`Package: ${engagement.package || "Unknown"}`)
  lines.push(`Assessed: ${formatDate(engagement.createdAt)}`)
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
  const [dbLoading, setDbLoading] = useState(false)
  const [dbError, setDbError] = useState("")
  const [session, setSession] = useState(null)
  const [view, setView] = useState("list") // list | active | new
  const [activeId, setActiveId] = useState(null)
  const [showExport, setShowExport] = useState(false)
  const [timerRunning, setTimerRunning] = useState(false)
  const [newForm, setNewForm] = useState({ clientName: "", company: "", package: "Business Security Assessment — $1,500", licenseType: "", userCount: "", reviewerName: "", reviewDate: todayISODate(), scope: "", notes: "" })
  const timerRef = useRef(null)

  useEffect(() => {
    if (!SUPABASE_CONFIGURED) { setLoaded(true); return }
    // SSO: accept a Supabase session handed over from the OS Hub via the URL hash
    // (#sso_session=<base64 json>) and persist it like a normal login.
    try {
      const m = (window.location.hash || "").match(/sso_session=([^&]+)/)
      if (m) {
        const json = decodeURIComponent(escape(atob(decodeURIComponent(m[1]))))
        JSON.parse(json) // validate
        localStorage.setItem(AUTH_STORAGE_KEY, json)
        history.replaceState(null, "", window.location.pathname + window.location.search)
      }
    } catch {}
    try {
      const raw = localStorage.getItem(AUTH_STORAGE_KEY)
      if (raw) {
        const stored = JSON.parse(raw)
        if (!stored.expires_at || stored.expires_at * 1000 > Date.now()) setSession(stored)
        else localStorage.removeItem(AUTH_STORAGE_KEY)
      }
    } catch {
      localStorage.removeItem(AUTH_STORAGE_KEY)
    }
    setLoaded(true)
  }, [])

  useEffect(() => {
    if (!loaded || !session) return
    let cancelled = false
    setDbLoading(true)
    setDbError("")
    loadReviewsFromSupabase(session)
      .then(rows => { if (!cancelled) setEngagements(rows) })
      .catch(e => { if (!cancelled) setDbError(e.message || "Unable to load assessments.") })
      .finally(() => { if (!cancelled) setDbLoading(false) })
    return () => { cancelled = true }
  }, [loaded, session])

  // Timer
  useEffect(() => {
    if (timerRunning && activeId) {
      timerRef.current = setInterval(() => {
        let nextDuration = null
        setEngagements(es => es.map(e => {
          if (e.id !== activeId) return e
          nextDuration = (e.duration || 0) + 1000
          return { ...e, duration: nextDuration }
        }))
        if (session && nextDuration && nextDuration % 10000 === 0) {
          patchReview(session, activeId, { duration_ms: nextDuration }).catch(e => setDbError(e.message || "Unable to save timer."))
        }
      }, 1000)
    } else {
      clearInterval(timerRef.current)
    }
    return () => clearInterval(timerRef.current)
  }, [timerRunning, activeId, session])

  const active = engagements.find(e => e.id === activeId)

  const handleAuthSuccess = (authSession) => {
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(authSession))
    setSession(authSession)
  }

  const signOut = async () => {
    try {
      if (session) await supabaseRequest("/auth/v1/logout", { method: "POST", session })
    } catch {}
    localStorage.removeItem(AUTH_STORAGE_KEY)
    setSession(null)
    setEngagements([])
    setActiveId(null)
    setView("list")
    setTimerRunning(false)
  }

  const createEngagement = async () => {
    if (!newForm.clientName || !newForm.company || !newForm.reviewerName || !newForm.reviewDate || !newForm.scope) { alert("Client name, company, assessor name, assessment date, and scope are required."); return }
    if (!session) { setDbError("Sign in before creating an assessment."); return }
    setDbError("")
    try {
      const eng = await createReviewInSupabase(newForm, session)
      setEngagements(es => [eng, ...es])
      setActiveId(eng.id)
      setView("active")
      setTimerRunning(true)
      setNewForm({ clientName: "", company: "", package: "Business Security Assessment — $1,500", licenseType: "", userCount: "", reviewerName: "", reviewDate: todayISODate(), scope: "", notes: "" })
    } catch (e) {
      setDbError(e.message || "Unable to create assessment.")
    }
  }

  const setCheckResult = (checkId, result) => {
    const current = engagements.find(e => e.id === activeId)?.checks?.[checkId] || {}
    const nextItem = { ...current, result }
    setEngagements(es => es.map(e => e.id === activeId
      ? { ...e, checks: { ...e.checks, [checkId]: nextItem } }
      : e
    ))
    if (session && activeId) upsertReviewItem(session, activeId, checkId, nextItem).catch(e => setDbError(e.message || "Unable to save checklist item."))
  }

  const setCheckNotes = (checkId, notes) => {
    const current = engagements.find(e => e.id === activeId)?.checks?.[checkId] || {}
    const nextItem = { ...current, notes }
    setEngagements(es => es.map(e => e.id === activeId
      ? { ...e, checks: { ...e.checks, [checkId]: nextItem } }
      : e
    ))
    if (session && activeId) upsertReviewItem(session, activeId, checkId, nextItem).catch(e => setDbError(e.message || "Unable to save checklist note."))
  }

  const updateEngagementField = (field, val) => {
    const columnMap = { reviewerName: "reviewer_name", reviewDate: "review_date", scope: "scope", secureScoreNotes: "secure_score_notes", duration: "duration_ms" }
    setEngagements(es => es.map(e => e.id === activeId ? { ...e, [field]: val } : e))
    const column = columnMap[field]
    if (session && activeId && column) patchReview(session, activeId, { [column]: val }).catch(e => setDbError(e.message || "Unable to save assessment field."))
  }

  const deleteEngagement = async (id) => {
    if (!session) return
    try {
      await deleteReviewFromSupabase(session, id)
      setEngagements(es => es.filter(e => e.id !== id))
      if (activeId === id) { setActiveId(null); setView("list") }
    } catch (e) {
      setDbError(e.message || "Unable to delete assessment.")
    }
  }

  if (!loaded) return (
    <div className="min-h-screen bg-[#080d14] flex items-center justify-center">
      <p className="text-[13px] font-mono text-[#3d5a7a] animate-pulse">Loading checklists…</p>
    </div>
  )

  if (!SUPABASE_CONFIGURED) return <MissingSupabaseConfig />

  if (!session) return <LoginView onAuth={handleAuthSuccess} />

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
            <button onClick={signOut}
              className="text-[11px] font-mono text-[#7a9abf] border border-[#1a2d45] px-3 py-2 rounded-lg hover:text-[#e8f0fe] hover:border-[#1e3a5f] transition-colors">
              Sign out
            </button>
            {view === "active" && (
              <>
                <button onClick={() => { setShowExport(true); setTimerRunning(false) }}
                  className="text-[13px] font-mono text-white bg-green-600 px-4 py-2 rounded-lg hover:bg-green-700 transition-colors">
                  Generate Report
                </button>
                <button onClick={() => { setView("list"); setTimerRunning(false) }}
                  className="text-[13px] font-mono text-[#7a9abf] border border-[#1a2d45] px-4 py-2 rounded-lg hover:text-[#e8f0fe] hover:border-[#1e3a5f] transition-colors">
                  ← All Assessments
                </button>
              </>
            )}
            {view === "list" && (
              <button onClick={() => setView("new")}
                className="text-[13px] font-mono text-white bg-[#3b82f6] px-4 py-2 rounded-lg hover:bg-[#2563eb] transition-colors">
                + New Assessment
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
        {dbError && (
          <div className="mb-4 bg-red-500/10 border border-red-500/30 rounded-xl p-3 text-[12px] text-red-300">
            {dbError}
          </div>
        )}
        {dbLoading && (
          <div className="mb-4 bg-[#0d1520] border border-[#1a2d45] rounded-xl p-3 text-[12px] text-[#7a9abf]">
            Loading secure assessment history…
          </div>
        )}

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
          session={session}
          onClose={() => setShowExport(false)}
        />
      )}
    </div>
  )
}


function MissingSupabaseConfig() {
  return (
    <div className="min-h-screen bg-[#080d14] text-[#e8f0fe] flex items-center justify-center px-5">
      <div className="max-w-lg bg-[#0d1520] border border-amber-500/30 rounded-xl p-6">
        <p className="text-[11px] font-mono text-amber-300 uppercase tracking-wider mb-2">Supabase configuration required</p>
        <h1 className="text-[20px] font-semibold mb-2">Secure assessment storage is not configured yet.</h1>
        <p className="text-[13px] text-[#7a9abf] leading-relaxed mb-4">
          Phase 2A requires Supabase Auth and RLS-backed persistence before assessments can be created or viewed.
          Add the public Supabase URL and anon key to your environment, then apply the SQL migration in <span className="font-mono text-[#e8f0fe]">supabase/migrations/001_initial_schema.sql</span>.
        </p>
        <div className="bg-[#080d14] border border-[#1a2d45] rounded-lg p-3 text-[12px] font-mono text-[#e8f0fe] space-y-1">
          <p>NEXT_PUBLIC_SUPABASE_URL=...</p>
          <p>NEXT_PUBLIC_SUPABASE_ANON_KEY=...</p>
        </div>
      </div>
    </div>
  )
}

function LoginView({ onAuth }) {
  const [mode, setMode] = useState("signin")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [fullName, setFullName] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [message, setMessage] = useState("")

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError("")
    setMessage("")
    try {
      const data = mode === "signup"
        ? await authRequest("/auth/v1/signup", { email, password, data: { full_name: fullName } })
        : await authRequest("/auth/v1/token?grant_type=password", { email, password })
      if (data.access_token) onAuth(data)
      else setMessage("Check your email to confirm the account, then sign in.")
    } catch (e) {
      setError(e.message || "Authentication failed.")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#080d14] text-[#e8f0fe] flex items-center justify-center px-5">
      <form onSubmit={submit} className="w-full max-w-sm bg-[#0d1520] border border-[#1a2d45] rounded-xl p-6 space-y-4">
        <div>
          <p className="text-[11px] font-mono text-[#60a5fa] uppercase tracking-wider mb-1">Amazin Cyber</p>
          <h1 className="text-[20px] font-semibold">{mode === "signup" ? "Create operator account" : "Sign in"}</h1>
          <p className="text-[12px] text-[#7a9abf] mt-1">Authenticated Supabase storage is required for client assessments.</p>
        </div>
        {mode === "signup" && (
          <div>
            <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Name</label>
            <input value={fullName} onChange={e => setFullName(e.target.value)}
              className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] focus:outline-none focus:border-[#3b82f6]" />
          </div>
        )}
        <div>
          <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Email</label>
          <input type="email" value={email} onChange={e => setEmail(e.target.value)} required
            className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] focus:outline-none focus:border-[#3b82f6]" />
        </div>
        <div>
          <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Password</label>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} required minLength={6}
            className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] focus:outline-none focus:border-[#3b82f6]" />
        </div>
        {error && <p className="text-[12px] text-red-300 bg-red-500/10 border border-red-500/30 rounded-lg p-2">{error}</p>}
        {message && <p className="text-[12px] text-green-300 bg-green-500/10 border border-green-500/30 rounded-lg p-2">{message}</p>}
        <button disabled={busy} className="w-full text-[14px] font-mono text-white bg-[#3b82f6] py-2.5 rounded-lg hover:bg-[#2563eb] disabled:opacity-60 transition-colors">
          {busy ? "Please wait…" : mode === "signup" ? "Create account" : "Sign in"}
        </button>
        <button type="button" onClick={() => setMode(mode === "signup" ? "signin" : "signup")}
          className="w-full text-[12px] text-[#7a9abf] hover:text-[#e8f0fe] transition-colors">
          {mode === "signup" ? "Already have an account? Sign in" : "Need an account? Create one"}
        </button>
      </form>
    </div>
  )
}

// ── NEW REVIEW FORM ────────────────────────────────────────────────────────
function NewReviewForm({ form, setForm, onCreate }) {
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))
  const PACKAGES = PROPOSAL_PACKAGES
  const LICENSES = ["Microsoft 365 Business Basic", "Microsoft 365 Business Standard", "Microsoft 365 Business Premium", "Mixed / Not sure"]
  return (
    <div className="max-w-lg mx-auto">
      <div className="mb-6">
        <p className="text-[11px] font-mono text-[#60a5fa] uppercase tracking-wider mb-1">New Security Assessment</p>
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
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Assessor Name *</label>
            <input value={form.reviewerName} onChange={e => set("reviewerName", e.target.value)}
              placeholder="Oshé"
              className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors" />
          </div>
          <div>
            <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Assessment Date *</label>
            <input type="date" value={form.reviewDate} onChange={e => set("reviewDate", e.target.value)}
              className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors" />
          </div>
        </div>
        <div>
          <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Assessment Scope *</label>
          <textarea value={form.scope} onChange={e => set("scope", e.target.value)} rows={3}
            placeholder="Example: Microsoft 365 tenant security settings assessed through Entra ID, Exchange admin center, Defender, SharePoint, and Secure Score."
            className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors resize-none" />
        </div>
        <div>
          <label className="block text-[11px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Pre-Assessment Notes</label>
          <textarea value={form.notes} onChange={e => set("notes", e.target.value)} rows={3}
            placeholder="Known concerns, context from discovery call, specific areas to focus on..."
            className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[13px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors resize-none" />
        </div>
        <button onClick={onCreate}
          className="w-full text-[14px] font-mono text-white bg-[#3b82f6] py-2.5 rounded-lg hover:bg-[#2563eb] transition-colors">
          Start Assessment →
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
      <p className="text-[15px] font-semibold text-[#e8f0fe] mb-1">No assessments yet</p>
      <p className="text-[13px] text-[#7a9abf] mb-5">Start a new assessment to run your first M365 security checklist.</p>
      <button onClick={onNew} className="text-[13px] font-mono text-white bg-[#3b82f6] px-5 py-2 rounded-lg hover:bg-[#2563eb] transition-colors">+ New Assessment</button>
    </div>
  )
  return (
    <div className="space-y-3">
      <p className="text-[11px] font-mono text-[#3d5a7a] uppercase tracking-wider mb-4">{engagements.length} assessment{engagements.length !== 1 ? "s" : ""}</p>
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
                <button onClick={e => { e.stopPropagation(); if (window.confirm("Delete this assessment?")) onDelete(eng.id) }}
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
  const qualityIssues = getReportQualityIssues(engagement)

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
            {(() => { const g = calcGrade(engagement.checks); return g ? (
              <div className="text-center px-3 py-1 rounded-lg border" style={{ background: g.bg, borderColor: g.border }}>
                <p className="text-[20px] font-bold leading-tight" style={{ color: g.color }}>{g.grade}{g.plus ? "+" : g.minus ? "−" : ""}</p>
                <p className="text-[10px] font-mono text-[#3d5a7a] uppercase">Grade</p>
              </div>
            ) : null })()}
          </div>
        </div>
        <div className="mt-3 h-1.5 bg-[#1a2d45] rounded-full overflow-hidden">
          <div className="h-full bg-gradient-to-r from-[#3b82f6] to-[#60a5fa] rounded-full transition-all duration-300" style={{ width: `${pct}%` }} />
        </div>
      </div>

      {/* Report quality gate */}
      <div className={`border rounded-xl p-4 mb-5 ${qualityIssues.length ? "bg-amber-500/10 border-amber-500/30" : "bg-green-500/10 border-green-500/30"}`}>
        <div className="flex items-start justify-between gap-3 mb-3">
          <div>
            <p className={`text-[12px] font-semibold ${qualityIssues.length ? "text-amber-300" : "text-green-300"}`}>Report Quality Gate</p>
            <p className="text-[11px] text-[#7a9abf]">Client reports require scope, assessor, date, and minimum completion before generation.</p>
          </div>
          <span className={`text-[10px] font-mono px-2 py-1 rounded border ${qualityIssues.length ? "text-amber-300 border-amber-500/30" : "text-green-300 border-green-500/30"}`}>
            {qualityIssues.length ? `${qualityIssues.length} blocker${qualityIssues.length === 1 ? "" : "s"}` : "Ready"}
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
          <div>
            <label className="block text-[10px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Assessor Name *</label>
            <input value={engagement.reviewerName || ""} onChange={e => onUpdateField("reviewerName", e.target.value)}
              placeholder="Assessor name"
              className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[12px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors" />
          </div>
          <div>
            <label className="block text-[10px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Assessment Date *</label>
            <input type="date" value={engagement.reviewDate || ""} onChange={e => onUpdateField("reviewDate", e.target.value)}
              className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[12px] text-[#e8f0fe] focus:outline-none focus:border-[#3b82f6] transition-colors" />
          </div>
        </div>
        <div>
          <label className="block text-[10px] font-mono text-[#7a9abf] mb-1 uppercase tracking-wider">Assessment Scope *</label>
          <textarea value={engagement.scope || ""} onChange={e => onUpdateField("scope", e.target.value)} rows={3}
            placeholder="Describe the tenant, tools, and M365 areas assessed."
            className="w-full bg-[#111d2e] border border-[#1a2d45] rounded-lg px-3 py-2 text-[12px] text-[#e8f0fe] placeholder-[#3d5a7a] focus:outline-none focus:border-[#3b82f6] transition-colors resize-none" />
        </div>
        {qualityIssues.length > 0 && (
          <ul className="mt-3 space-y-1">
            {qualityIssues.map(issue => <li key={issue} className="text-[11px] text-amber-200">• {issue}</li>)}
          </ul>
        )}
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
function ExportModal({ engagement, session, onClose }) {
  const [stage, setStage] = useState("ready") // ready | generating | done | error
  const [report, setReport] = useState(null)
  const [errorMsg, setErrorMsg] = useState("")
  const [proposalStatus, setProposalStatus] = useState("")

  const { pass, fail } = calcScore(engagement.checks)
  const total = pass + fail
  const pct = total ? Math.round((pass / total) * 100) : 0
  const grade = calcGrade(engagement.checks)
  const gradeSuffix = grade ? (grade.plus ? "+" : grade.minus ? "−" : "") : ""
  const gradeLabel = grade ? `${grade.grade}${gradeSuffix}` : null
  const qualityIssues = getReportQualityIssues(engagement)
  const canGenerateReport = qualityIssues.length === 0

  useEffect(() => {
    let cancelled = false
    if (!session || !engagement?.id) return
    loadLatestGeneratedReport(session, engagement.id)
      .then(savedReport => {
        if (!cancelled && savedReport) {
          setReport(savedReport)
          setStage("done")
        }
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [session, engagement?.id])

  async function generateReport() {
    if (!canGenerateReport) {
      setErrorMsg(`Report is not ready: ${qualityIssues.join(" ")}`)
      setStage("error")
      return
    }

    setStage("generating")
    setErrorMsg("")

    try {
      const res = await fetch("/api/generate-report", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session?.access_token || ""}`,
        },
        body: JSON.stringify({ reviewId: engagement.id })
      })
      const data = await res.json()
      if (!res.ok) {
        const msg = data?.error || `Error ${res.status}`
        throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg))
      }
      setReport(data.report)
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
            <p className="text-[11px] font-mono text-[#60a5fa] uppercase tracking-wider mb-0.5">Assessment Complete</p>
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
                {gradeLabel && grade && (
                  <div className="text-center px-3 py-1 rounded-lg border" style={{ background: grade.bg, borderColor: grade.border }}>
                    <p className="text-[18px] font-bold leading-tight" style={{ color: grade.color }}>{gradeLabel}</p>
                    <p className="text-[10px] font-mono text-[#3d5a7a]">GRADE</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* READY state */}
          {stage === "ready" && (
            <>
              <div className="bg-[#111d2e] border border-[#1a2d45] rounded-xl p-4 mb-5">
                <p className="text-[12px] font-semibold text-[#e8f0fe] mb-1">What happens next</p>
                <p className="text-[12px] text-[#7a9abf] leading-relaxed">The server will validate your structured checklist data, apply locked report instructions, and write a plain-English report — executive summary, prioritized findings with explanations, and what's working well.</p>
              </div>
              {!canGenerateReport && (
                <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 mb-4">
                  <p className="text-[12px] font-semibold text-amber-300 mb-2">Report blocked until quality gates are complete</p>
                  <ul className="space-y-1">
                    {qualityIssues.map(issue => <li key={issue} className="text-[11px] text-amber-200">• {issue}</li>)}
                  </ul>
                </div>
              )}
              <button onClick={generateReport} disabled={!canGenerateReport}
                className={`w-full text-[14px] font-mono text-white py-3 rounded-xl transition-colors ${canGenerateReport ? "bg-[#3b82f6] hover:bg-[#2563eb]" : "bg-[#1a2d45] cursor-not-allowed opacity-60"}`}>
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
                <button onClick={async () => {
                  const summary = buildProposalSummary(engagement, pass, fail, pct)
                  // Prefill only the non-sensitive package selection via the URL.
                  // Client name, company, and findings are never passed in the URL.
                  const proposalPackage = proposalPackageFor(engagement.package)
                  const url = `https://proposals.amazincyber.com/?package=${encodeURIComponent(proposalPackage)}`
                  try {
                    await navigator.clipboard?.writeText(summary)
                    setProposalStatus(`Opened the proposal tool with the ${proposalPackage} package pre-selected. A remediation summary was copied for manual paste.`)
                  } catch {
                    setProposalStatus(`Opened the proposal tool with the ${proposalPackage} package pre-selected. Copy findings manually from this report.`)
                  }
                  window.open(url, "_blank", "noopener,noreferrer")
                }}
                  className="flex-1 text-[12px] font-mono text-white bg-purple-600 py-2 rounded-lg hover:bg-purple-700 transition-colors">
                  Open Proposal Tool →
                </button>
                <button onClick={() => setStage("ready")}
                  className="text-[12px] font-mono text-[#7a9abf] border border-[#1a2d45] px-4 py-2 rounded-lg hover:text-[#e8f0fe] hover:border-[#1e3a5f] transition-colors">
                  Regenerate
                </button>
              </div>
              {proposalStatus && (
                <p className="text-[11px] text-purple-200 bg-purple-500/10 border border-purple-500/30 rounded-lg px-3 py-2 mb-4">{proposalStatus}</p>
              )}

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
                    <span>Assessed: <strong style={{ color: "#374151" }}>{formatDate(engagement.reviewDate || engagement.createdAt)}</strong></span>
                    {engagement.duration > 0 && <span>Duration: <strong style={{ color: "#374151" }}>{formatDuration(engagement.duration)}</strong></span>}
                  </div>
                </div>

                {/* Score row */}
                {(() => {
                  const grade = calcGrade(engagement.checks)
                  const gradeSuffix = grade ? (grade.plus ? "+" : grade.minus ? "−" : "") : ""
                  const gradeLabel = grade ? `${grade.grade}${gradeSuffix}` : "—"
                  const gradeColor = grade?.color || "#6b7280"
                  const gradeBg = grade?.bg || "#f9fafb"
                  const gradeBorder = grade?.border || "#e5e7eb"
                  return (
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 10, marginBottom: 22 }}>
                      {[["PASSING", pass, "#15803d"], ["NEEDS ATTENTION", fail, "#b91c1c"], ["OVERALL SCORE", `${pct}%`, "#1d4ed8"]].map(([lbl, val, col]) => (
                        <div key={lbl} style={{ background: "#f9fafb", borderRadius: 8, padding: "12px 14px", textAlign: "center", border: "1px solid #f3f4f6" }}>
                          <div style={{ fontSize: 26, fontWeight: 600, color: col, lineHeight: 1 }}>{val}</div>
                          <div style={{ fontSize: 10, color: "#9ca3af", marginTop: 4, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.06em" }}>{lbl}</div>
                        </div>
                      ))}
                      <div style={{ background: gradeBg, borderRadius: 8, padding: "12px 14px", textAlign: "center", border: `1px solid ${gradeBorder}` }}>
                        <div style={{ fontSize: 26, fontWeight: 700, color: gradeColor, lineHeight: 1 }}>{gradeLabel}</div>
                        <div style={{ fontSize: 10, color: "#9ca3af", marginTop: 4, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.06em" }}>SECURITY GRADE</div>
                      </div>
                    </div>
                  )
                })()}

                {/* Executive summary */}
                <div style={{ background: "#fef9f2", borderLeft: "3px solid #d97706", borderRadius: "0 8px 8px 0", padding: "12px 16px", marginBottom: 22 }}>
                  <p style={{ fontFamily: "monospace", fontSize: 10, textTransform: "uppercase", letterSpacing: "0.1em", color: "#d97706", marginBottom: 8 }}>Executive Summary</p>
                  <p style={{ fontSize: 14, color: "#374151", lineHeight: 1.7, margin: 0 }}>{report.executiveSummary}</p>
                </div>

                <div style={{ background: "#f9fafb", border: "1px solid #e5e7eb", borderRadius: 8, padding: "10px 12px", marginBottom: 20 }}>
                  <p style={{ fontFamily: "monospace", fontSize: 10, textTransform: "uppercase", letterSpacing: "0.1em", color: "#6b7280", marginBottom: 6 }}>Scope + Limitations</p>
                  <p style={{ fontSize: 12, color: "#4b5563", lineHeight: 1.6, margin: 0 }}>{report.scopeAndLimitations || engagement.scope}</p>
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

                {/* Priority Actions */}
                {report.priorityActions && (
                  <div style={{ marginBottom: 20 }}>
                    <p style={{ fontSize: 16, fontWeight: 600, color: "#111", borderBottom: "1px solid #e5e7eb", paddingBottom: 8, marginBottom: 14 }}>Priority Actions</p>
                    {[
                      { key: "immediate", label: "Immediate — This Week", dot: "#dc2626", bg: "#fff7f7", border: "#fecaca" },
                      { key: "thirtyDays", label: "Next 30 Days", dot: "#d97706", bg: "#fffbf0", border: "#fde68a" },
                      { key: "future", label: "Future Improvements", dot: "#1d4ed8", bg: "#f0f7ff", border: "#bfdbfe" },
                    ].map(({ key, label, dot, bg, border }) => {
                      const items = report.priorityActions[key]
                      if (!items?.length) return null
                      return (
                        <div key={key} style={{ marginBottom: 12 }}>
                          <p style={{ fontSize: 11, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.08em", color: dot, marginBottom: 6, fontWeight: 600 }}>{label}</p>
                          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                            {items.map((item, i) => (
                              <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8, padding: "7px 10px", background: bg, borderRadius: 6, border: `1px solid ${border}` }}>
                                <span style={{ fontFamily: "monospace", fontSize: 11, color: dot, fontWeight: 700, flexShrink: 0, marginTop: 1 }}>{i + 1}.</span>
                                <span style={{ fontSize: 13, color: "#374151", lineHeight: 1.5 }}>{item}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )
                    })}
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
                  <span>Prepared by {engagement.reviewerName ? `${engagement.reviewerName} — Assessor` : "Amazin Cyber"} · Amazin Cyber Solutions · amazincyber.com</span>
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
