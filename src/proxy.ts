import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

/**
 * Aktualisiert die Supabase-Session (Cookies) und leitet nicht angemeldete Nutzer
 * von geschützten Bereichen um. Dies ist nur eine optimistische Prüfung –
 * die verbindliche Autorisierung erfolgt serverseitig in jeder Seite/Aktion und per RLS.
 */
export async function proxy(request: NextRequest) {
  let response = NextResponse.next({ request });
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
        response = NextResponse.next({ request });
        cookiesToSet.forEach(({ name, value, options }) => response.cookies.set(name, value, options));
      },
    },
  });
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const path = request.nextUrl.pathname;
  const protectedArea = path.startsWith("/app") || path.startsWith("/onboarding") || path.startsWith("/admin");
  if (protectedArea && !user) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.search = `?next=${encodeURIComponent(path)}`;
    return NextResponse.redirect(url);
  }
  return response;
}

export const config = {
  matcher: ["/app/:path*", "/onboarding/:path*", "/admin/:path*", "/login", "/register", "/auth/:path*"],
};
