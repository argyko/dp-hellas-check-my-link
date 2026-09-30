import { NextRequest } from "next/server";

const API_BASE = (process.env.CHECK_MY_LINK_API_URL || "http://backend:8000").replace(/\/$/, "");
const API_KEY = process.env.CHECK_MY_LINK_API_KEY || "";

export function assertBffConfigured() {
  if (!API_KEY) throw new Error("CHECK_MY_LINK_API_KEY is not configured");
}

export function assertSameOrigin(request: NextRequest) {
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (origin) {
    const expected = `${request.nextUrl.protocol}//${host}`;
    if (origin !== expected) throw new Error("Cross-origin request rejected");
  }
}

export function clientForwardHeaders(request: NextRequest) {
  const headers: Record<string, string> = { "X-API-Key": API_KEY };
  const clientIp = request.headers.get("x-real-ip");
  if (clientIp) headers["X-Forwarded-For"] = clientIp;
  return headers;
}

export async function backendFetch(request: NextRequest, path: string, init: RequestInit = {}) {
  assertBffConfigured();
  const headers = new Headers(init.headers);
  for (const [k, v] of Object.entries(clientForwardHeaders(request))) headers.set(k, v);
  return fetch(`${API_BASE}${path}`, { ...init, headers, cache: "no-store" });
}
