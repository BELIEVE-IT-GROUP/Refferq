import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { jwtVerify } from 'jose';

const JWT_SECRET = new TextEncoder().encode(
    process.env.JWT_SECRET!
);

export async function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;

    // 1. Define protected routes
    const isAdminRoute = pathname.startsWith('/api/admin') || pathname.startsWith('/admin');
    const isAffiliateRoute = pathname.startsWith('/api/affiliate') || pathname.startsWith('/affiliate');

    if (!isAdminRoute && !isAffiliateRoute) {
        return NextResponse.next();
    }

    // 2. Get token from cookies
    const token = request.cookies.get('auth-token')?.value;

    if (!token) {
        // If it's an API route, return 401
        if (pathname.startsWith('/api/')) {
            return NextResponse.json(
                { error: 'Authentication required' },
                { status: 401 }
            );
        }
        // If it's a page route, redirect to login
        return NextResponse.redirect(new URL('/login', request.url));
    }

    try {
        // 3. Verify JWT
        const { payload } = await jwtVerify(token, JWT_SECRET);
        const userRole = payload.role as string;

        // 4. Role-based access control
        if (isAdminRoute && userRole !== 'ADMIN') {
            if (pathname.startsWith('/api/')) {
                return NextResponse.json(
                    { error: 'Forbidden: Admin access required' },
                    { status: 403 }
                );
            }
            return NextResponse.redirect(new URL('/login', request.url));
        }

        if (isAffiliateRoute && userRole !== 'AFFILIATE' && userRole !== 'ADMIN') {
            if (pathname.startsWith('/api/')) {
                return NextResponse.json(
                    { error: 'Forbidden: Affiliate access required' },
                    { status: 403 }
                );
            }
            return NextResponse.redirect(new URL('/login', request.url));
        }

        // BELIEVE: middleware only gates here. Route handlers read the user
        // straight from the auth-token cookie via getAuthFromRequest()
        // (src/lib/auth-request.ts) instead of an x-user-id header --
        // NextResponse.next({request:{headers}}) does not forward custom
        // headers to the route handler in this self-hosted/Turbopack build
        // (tried both Edge and Node.js middleware runtimes, same result),
        // so a header-based handoff here silently loses the value.
        return NextResponse.next();
    } catch (error) {
        if (pathname.startsWith('/api/')) {
            return NextResponse.json(
                { error: 'Invalid or expired token' },
                { status: 401 }
            );
        }
        return NextResponse.redirect(new URL('/login', request.url));
    }
}

// See "Matching Paths" below to learn more
export const config = {
    matcher: [
        '/admin/:path*',
        '/affiliate/:path*',
        '/api/admin/:path*',
        '/api/affiliate/:path*',
        '/api/auth/me',
    ],
};
