import { NextRequest, NextResponse } from "next/server";
import { assertSameOrigin, backendFetch } from "@/lib/backend";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    assertSameOrigin(request);
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (contentLength > 16 * 1024) return NextResponse.json({ detail: "Request too large." }, { status: 413 });
    const body = await request.json();
    if (typeof body?.url !== "string" || body.url.length > 4096) return NextResponse.json({ detail: "Μη έγκυρο URL." }, { status: 400 });
    const upstream = await backendFetch(request, "/api/v1/scan", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: body.url }),
    });
    const data = await upstream.json();
    return NextResponse.json(data, { status: upstream.status });
  } catch (error) {
    const message = error instanceof Error ? error.message : "BFF request failed";
    return NextResponse.json({ detail: message }, { status: message.includes("Cross-origin") ? 403 : 503 });
  }
}
