import { NextRequest, NextResponse } from "next/server";
import { assertSameOrigin, backendFetch } from "@/lib/backend";

export const runtime = "nodejs";

export async function GET(request: NextRequest, { params }: { params: { scanId: string } }) {
  try {
    assertSameOrigin(request);
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(params.scanId)) return NextResponse.json({ detail: "Invalid scan id." }, { status: 400 });
    const upstream = await backendFetch(request, `/api/v1/scan/${encodeURIComponent(params.scanId)}`);
    const data = await upstream.json();
    return NextResponse.json(data, { status: upstream.status });
  } catch (error) {
    const message = error instanceof Error ? error.message : "BFF request failed";
    return NextResponse.json({ detail: message }, { status: message.includes("Cross-origin") ? 403 : 503 });
  }
}
