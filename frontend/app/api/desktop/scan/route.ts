import { NextRequest, NextResponse } from "next/server";
import { backendFetch } from "@/lib/backend";
export const runtime="nodejs";
const MAX=4096;
export async function POST(request:NextRequest){
  try{
    if(request.headers.get("x-dp-desktop")!=="1") return NextResponse.json({detail:"Desktop client required."},{status:403});
    const body=await request.json();
    if(typeof body?.url!=="string"||body.url.length>MAX) return NextResponse.json({detail:"Μη έγκυρο URL."},{status:400});
    const u=body.url.trim(); if(!/^https?:\/\//i.test(u)) return NextResponse.json({detail:"Υποστηρίζονται μόνο HTTP/HTTPS URLs."},{status:400});
    const upstream=await backendFetch(request,"/api/v1/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:u})});
    return NextResponse.json(await upstream.json(),{status:upstream.status});
  }catch(e){return NextResponse.json({detail:e instanceof Error?e.message:"BFF request failed"},{status:503})}
}
