import { NextResponse } from 'next/server'

const COOKIE_NAME = 'op_session'
const MAX_AGE = 60 * 60 * 24 * 30 // 30 days

const ALLOWED_ORIGINS = new Set(['https://os.amazincyber.com'])

function corsHeaders(origin) {
  const h = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  }
  if (ALLOWED_ORIGINS.has(origin)) h['Access-Control-Allow-Origin'] = origin
  return h
}

export async function OPTIONS(req) {
  const origin = req.headers.get('origin') || ''
  return new NextResponse(null, { status: 204, headers: corsHeaders(origin) })
}

export async function POST(req) {
  const origin = req.headers.get('origin') || ''
  const cors = corsHeaders(origin)
  const { password } = await req.json()

  if (!process.env.OPERATOR_SECRET || password !== process.env.OPERATOR_SECRET) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: cors })
  }

  const res = NextResponse.json({ ok: true }, { headers: cors })
  res.cookies.set(COOKIE_NAME, process.env.OPERATOR_SECRET, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: MAX_AGE,
    path: '/',
  })
  return res
}
