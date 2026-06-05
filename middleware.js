import { NextResponse } from 'next/server'

const COOKIE_NAME = 'op_session'
const LOGIN_PATH = '/login'

export function middleware(req) {
  const { pathname } = req.nextUrl
  if (pathname.startsWith(LOGIN_PATH)) return NextResponse.next()
  if (pathname.startsWith('/api/auth')) return NextResponse.next()

  const session = req.cookies.get(COOKIE_NAME)
  if (session?.value === process.env.OPERATOR_SECRET) return NextResponse.next()

  const loginUrl = req.nextUrl.clone()
  loginUrl.pathname = LOGIN_PATH
  loginUrl.searchParams.set('from', pathname)
  return NextResponse.redirect(loginUrl)
}

export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] }
