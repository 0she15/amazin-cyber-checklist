'use client'

import { Suspense, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  )
}

function LoginForm() {
  const router = useRouter()
  const params = useSearchParams()
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)

    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    })

    setLoading(false)
    if (res.ok) {
      router.push(params.get('from') ?? '/')
    } else {
      setError('Incorrect password.')
    }
  }

  return (
    <main style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#0a0f1a', padding: 16 }}>
      <form
        onSubmit={handleSubmit}
        style={{ boxSizing: 'border-box', width: 400, maxWidth: '100%', background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 40 }}
      >
        <p style={{ margin: 0, color: '#3b82f6', fontSize: 11, letterSpacing: '0.15em', textTransform: 'uppercase', fontWeight: 600 }}>
          Amazin Cyber
        </p>
        <h1 style={{ margin: '8px 0 0', color: '#ffffff', fontSize: 28, fontWeight: 700 }}>Sign in</h1>
        <p style={{ margin: '8px 0 28px', color: '#64748b', fontSize: 14 }}>Checklist — operator access</p>

        <label htmlFor="password" style={{ display: 'block', color: '#94a3b8', fontSize: 11, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8 }}>
          Password
        </label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoFocus
          required
          style={{ boxSizing: 'border-box', width: '100%', background: '#1e293b', border: '1px solid #334155', color: '#ffffff', borderRadius: 6, padding: '10px 14px', fontSize: 14, outline: 'none' }}
        />

        {error && <p style={{ color: '#ef4444', fontSize: 13, margin: '12px 0 0' }}>{error}</p>}

        <button
          type="submit"
          disabled={loading}
          style={{ width: '100%', marginTop: 24, background: '#3b82f6', color: '#ffffff', border: 'none', borderRadius: 6, padding: '11px 14px', fontSize: 14, fontWeight: 600, cursor: loading ? 'default' : 'pointer', opacity: loading ? 0.7 : 1 }}
        >
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  )
}
