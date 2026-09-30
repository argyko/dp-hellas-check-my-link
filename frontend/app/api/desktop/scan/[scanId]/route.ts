import {NextRequest,NextResponse} from "next/server";
import {backendFetch} from "@/lib/backend";
export const runtime="nodejs";
export async function GET(request:NextRequest,{params}:{params:{scanId:string}}){
 try{
  if(request.headers.get("x-dp-desktop")!=="1") return NextResponse.json({detail:"Desktop client required."},{status:403});
  if(!/^[A-Za-z0-9_-]{8,128}$/.test(params.scanId)) return NextResponse.json({detail:"Invalid scan id."},{status:400});
  const upstream=await backendFetch(request,`/api/v1/scan/${encodeURIComponent(params.scanId)}`);
  return NextResponse.json(await upstream.json(),{status:upstream.status});
 }catch(e){return NextResponse.json({detail:e instanceof Error?e.message:"BFF request failed"},{status:503})}
}
