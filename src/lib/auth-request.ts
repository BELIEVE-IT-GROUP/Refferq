import { NextRequest } from 'next/server';
import { jwtVerify } from 'jose';

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET!);

export interface AuthUser {
  userId: string;
  role: string;
}

/**
 * BELIEVE: reads the auth-token cookie directly instead of relying on the
 * x-user-id/x-user-role headers middleware.ts tries to inject via
 * NextResponse.next({request:{headers}}) -- that mechanism silently drops
 * the headers in this self-hosted/Turbopack build regardless of Edge vs
 * Node.js middleware runtime. middleware.ts still gates access; this is
 * the reliable way for a route handler to know who's making the request.
 */
export async function getAuthFromRequest(request: NextRequest): Promise<AuthUser | null> {
  const token = request.cookies.get('auth-token')?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return { userId: payload.userId as string, role: payload.role as string };
  } catch {
    return null;
  }
}
