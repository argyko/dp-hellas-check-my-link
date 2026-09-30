"use client";

import React, { useEffect, useState } from "react";

type ScanState = "idle" | "scanning" | "result" | "failed";
type Finding = { level?: string; title: string; text: string };
type ScanResult = {
  url?: string;
  risk?: {
    risk_score?: number;
    confidence_score?: number;
    status_label?: string;
    status?: string;
    signals?: Array<{ name?: string; severity?: string; reason?: string }>;
  };
  evidence?: {
    http?: { final_url?: string };
    browser?: { final_url?: string };
    ai_analysis?: { status?: string; summary?: string; findings?: Finding[] };
  };
};

type ScanResponse = {
  id?: string;
  scan_id?: string;
  status: string;
  error?: string | null;
  result?: ScanResult | null;
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [state, setState] = useState<ScanState>("idle");
  const [scanId, setScanId] = useState<string | null>(null);
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!scanId || state !== "scanning") return;
    let stopped = false;
    const poll = async () => {
      try {
        const response = await fetch(`/api/scan/${scanId}`, { cache: "no-store" });
        const data: ScanResponse = await response.json();
        if (stopped) return;
        setScan(data);
        if (["COMPLETED", "PARTIAL"].includes(data.status)) setState("result");
        else if (data.status === "FAILED") { setError(data.error || "Ο έλεγχος απέτυχε."); setState("failed"); }
      } catch { if (!stopped) { setError("Δεν ήταν δυνατή η επικοινωνία με το backend."); setState("failed"); } }
    };
    poll();
    const timer = window.setInterval(poll, 1200);
    return () => { stopped = true; window.clearInterval(timer); };
  }, [scanId, state]);

  const startScan = async () => {
    const value = url.trim();
    if (!value) return;
    setError(""); setScan(null); setState("scanning");
    try {
      const response = await fetch(`/api/scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: value }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Μη έγκυρο URL.");
      setScanId(data.scan_id); setScan(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Αποτυχία έναρξης ελέγχου."); setState("failed");
    }
  };

  const reset = () => { setState("idle"); setUrl(""); setScanId(null); setScan(null); setError(""); };
  const risk = scan?.result?.risk;
  const score = Math.max(0, Math.min(100, risk?.risk_score ?? 0));
  const confidence = Math.max(0, Math.min(100, risk?.confidence_score ?? 0));
  const finalUrl = scan?.result?.evidence?.http?.final_url || scan?.result?.evidence?.browser?.final_url || scan?.result?.url || url;
  const findings = risk?.signals?.map((s: { name?: string; severity?: string; reason?: string }) => ({ level: s.severity || "medium", title: s.name || "Security signal", text: s.reason || "Εντοπίστηκε σχετικό security signal." })) || scan?.result?.evidence?.ai_analysis?.findings || [];

  return <main className="shell">
    <header className="topbar"><div className="brand"><div className="brandMark">✓</div><span className="brandName"><span>DP Hellas Check My Link</span><small>LINK SECURITY</small></span></div><div className="privacy">Έλεγχος link με ασφάλεια και ιδιωτικότητα</div></header>

    {state === "idle" && <section className="hero"><div className="eyebrow">ΕΛΕΓΧΟΣ ΑΣΦΑΛΕΙΑΣ</div><h1>Έλεγξε ένα link<br /><span>πριν το ανοίξεις.</span></h1><p className="lead">Ανάλυση URL, domain, redirects, threat intelligence και ύποπτων χαρακτηριστικών σε μία απλή αναφορά.</p><div className="scannerCard"><label htmlFor="url">URL προς έλεγχο</label><div className="inputRow"><input id="url" value={url} onChange={(e: React.ChangeEvent<HTMLInputElement>)=>setUrl(e.target.value)} onKeyDown={(e: React.KeyboardEvent<HTMLInputElement>)=>e.key === "Enter" && startScan()} placeholder="https://example.com/..." autoComplete="off"/><button onClick={startScan} disabled={!url.trim()}>Έλεγχος Link</button></div><div className="hint">Μην εισάγεις κωδικούς ή προσωπικά στοιχεία.</div></div><div className="featureGrid"><Feature title="Threat Intelligence" text="Έλεγχος phishing και malware indicators."/><Feature title="Ανάλυση Redirects" text="Εντοπισμός τελικού προορισμού και redirects."/><Feature title="Risk Score" text="Αποτέλεσμα 0–100 με confidence."/></div></section>}

    {state === "scanning" && <section className="scanPage"><div className="scanCard"><div className="spinner"/><div className="eyebrow">LIVE SECURITY SCAN</div><h2>Αναλύουμε το link...</h2><p className="scanUrl">{url}</p><div className="progressTrack"><div className="progressFill"/></div><div className="steps"><Step text="Έλεγχος URL" done/><Step text="Domain & DNS" done/><Step text="Threat Intelligence" active/><Step text="SSL / Certificate"/><Step text="Web Analysis"/><Step text="Risk Calculation"/></div><div className="scanSafety"><span>🔒</span><div><strong>Μην εισάγεις στοιχεία</strong><small>Ο έλεγχος δεν χρειάζεται κωδικούς, κάρτες ή προσωπικά δεδομένα.</small></div></div></div></section>}

    {state === "failed" && <section className="scanPage"><div className="scanCard"><div className="eyebrow">ΑΠΟΤΥΧΙΑ ΕΛΕΓΧΟΥ</div><h2>Δεν ολοκληρώθηκε ο έλεγχος</h2><p className="scanUrl">{error}</p><button className="secondary" onClick={reset}>Νέα προσπάθεια</button></div></section>}

    {state === "result" && <section className="resultPage"><div className="resultHeader"><div><div className="eyebrow">ΑΠΟΤΕΛΕΣΜΑ ΕΛΕΓΧΟΥ</div><h2>Αποτέλεσμα ελέγχου</h2><p className="scanUrl">{scan?.result?.url || url}</p></div><button className="secondary" onClick={reset}>Νέος έλεγχος</button></div><div className="resultGrid"><div className="scoreCard"><div className="scoreRing"><span>{score}</span><small>/100</small></div><div className="riskLabel">{risk?.status_label || risk?.status || "ΑΓΝΩΣΤΟ"}</div><div className="confidence">Βαθμός αξιοπιστίας <strong>{confidence}%</strong></div><p>{scan?.status === "PARTIAL" ? "Ο έλεγχος ολοκληρώθηκε με περιορισμένα διαθέσιμα στοιχεία." : "Το αποτέλεσμα βασίζεται στα διαθέσιμα deterministic security signals."}</p><div className="actionDanger">{score >= 80 ? "ΜΗΝ ΑΝΟΙΞΕΙΣ ΤΟ LINK" : score >= 50 ? "ΑΠΑΙΤΕΙΤΑΙ ΠΡΟΣΟΧΗ" : "ΕΛΕΓΞΕ ΠΡΙΝ ΑΝΟΙΞΕΙΣ"}</div></div><div className="detailsCard"><div className="cardTitle">Κύρια ευρήματα</div><div className="findings">{findings.length ? findings.slice(0,8).map((f,i)=><div className={`finding ${f.level === "critical" || f.level === "high" ? "danger" : "warning"}`} key={`${f.title}-${i}`}><span>!</span><div><strong>{f.title}</strong><small>{f.text}</small></div></div>) : <div className="finding"><span>i</span><div><strong>Δεν υπάρχουν καταγεγραμμένα signals</strong><small>Αυτό δεν αποτελεί απόλυτη εγγύηση ασφάλειας.</small></div></div>}</div></div></div><div className="summaryCard"><div><div className="cardTitle">Τελικός προορισμός</div><code>{finalUrl}</code></div><div><div className="cardTitle">Κατάσταση</div><span className="statusBadge">{risk?.status_label || scan?.status || "UNKNOWN"}</span></div></div></section>}
    <footer><span>DP Hellas Check My Link • API connected</span><span>Το αποτέλεσμα είναι αξιολόγηση κινδύνου, όχι απόλυτη εγγύηση ασφάλειας.</span></footer>
  </main>;
}
function Feature({title,text}:{title:string;text:string}){return <div className="feature"><strong>{title}</strong><span>{text}</span></div>}
function Step({text,done,active}:{text:string;done?:boolean;active?:boolean}){return <div className={`step ${done?"done":""} ${active?"active":""}`}><span>{done?"✓":active?"●":"○"}</span><div><strong>{text}</strong><small>{done?"Ολοκληρώθηκε":active?"Σε εξέλιξη":"Αναμονή"}</small></div></div>}
