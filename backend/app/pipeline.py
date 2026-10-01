from __future__ import annotations
import time
from app.database import update_scan, add_scan_event
from app.observability import new_trace_id, log_event
from app.security.url_validator import validate_and_normalize_url, URLValidationError
from app.scanner.http_scanner import scan_url, ScanError
from app.scanner.browser_scanner import scan_page, BrowserScanError
from app.analyzers.web_content import analyze_web_content
from app.analyzers.domain import analyze_domain, DomainAnalysisError
from app.analyzers.tls import analyze_tls, TLSAnalysisError
from app.analyzers.url_intelligence import analyze_url_intelligence, detect_impersonation
from app.intelligence.threat_intel import analyze_threat_intelligence, ThreatIntelError
from app.scoring.correlation import correlate_threat_intelligence
from app.intelligence.evidence_model import build_unified_evidence
from app.scoring.correlation_v2 import correlate_all
from app.scoring.risk_engine import calculate_risk
from app.ai.openai_analyzer import analyze_with_openai, OpenAIAnalysisError


def _step(scan_id, trace_id, component, fn, *args, **kwargs):
    started = time.perf_counter()
    add_scan_event(scan_id, trace_id, "STEP_STARTED", component, status="RUNNING")
    log_event("scan.step.started", scan_id=scan_id, trace_id=trace_id, component=component)
    try:
        value = fn(*args, **kwargs)
        duration = round((time.perf_counter() - started) * 1000, 2)
        add_scan_event(
            scan_id, trace_id, "STEP_COMPLETED", component,
            status="OK", duration_ms=duration
        )
        log_event(
            "scan.step.completed",
            scan_id=scan_id, trace_id=trace_id,
            component=component, duration_ms=duration
        )
        return value
    except Exception as exc:
        duration = round((time.perf_counter() - started) * 1000, 2)
        add_scan_event(
            scan_id, trace_id, "STEP_FAILED", component,
            status="ERROR", duration_ms=duration,
            metadata={"error_type": type(exc).__name__}
        )
        log_event(
            "scan.step.failed",
            scan_id=scan_id, trace_id=trace_id,
            component=component, duration_ms=duration,
            error_type=type(exc).__name__
        )
        raise


def run_scan(scan_id, raw_url):
    trace_id = new_trace_id()
    started = time.perf_counter()
    add_scan_event(
        scan_id, trace_id, "SCAN_STARTED", "pipeline", status="RUNNING"
    )
    update_scan(scan_id, "RUNNING")
    log_event("scan.started", scan_id=scan_id, trace_id=trace_id)

    try:
        normalized = _step(
            scan_id, trace_id, "url_validation",
            validate_and_normalize_url, raw_url
        )
        http_result = _step(
            scan_id, trace_id, "http", scan_url, normalized
        )
        domain_result = _step(
            scan_id, trace_id, "domain", analyze_domain, normalized
        )
        tls_result = _step(
            scan_id, trace_id, "tls", analyze_tls, normalized
        )
        ui = _step(
            scan_id, trace_id, "url_intelligence",
            analyze_url_intelligence, normalized
        )
        impersonation = detect_impersonation(ui, domain_result)
        threat = _step(
            scan_id, trace_id, "threat_intelligence",
            analyze_threat_intelligence, normalized
        )
        corr = correlate_threat_intelligence(threat)
        browser = _step(
            scan_id, trace_id, "browser", scan_page, normalized
        )
        web = _step(
            scan_id, trace_id, "web_content",
            analyze_web_content, browser
        )

        try:
            ai = _step(
                scan_id, trace_id, "openai",
                analyze_with_openai,
                url=normalized,
                browser_result=browser,
                web_content=web,
            )
        except OpenAIAnalysisError as exc:
            ai = {
                "status": "UNAVAILABLE",
                "reason": str(exc),
                "ai_used_for_score": False,
            }
            add_scan_event(
                scan_id, trace_id, "STEP_DEGRADED", "openai",
                status="UNAVAILABLE",
                metadata={"reason": str(exc)}
            )

        unified = build_unified_evidence(
            threat=threat,
            domain=domain_result,
            tls=tls_result,
            http=http_result,
            url_intelligence=ui,
            browser=browser,
        )
        corr_all = correlate_all(unified, threat_correlation=corr)
        risk = calculate_risk(
            normalized,
            http_result,
            domain_result,
            tls_result,
            threat,
            corr_all,
            ui,
            impersonation,
            web,
        )
        result = {
            "url": normalized,
            "risk": risk,
            "evidence": {
                "http": http_result,
                "domain": domain_result,
                "tls": tls_result,
                "url_intelligence": ui,
                "impersonation": impersonation,
                "threat_intelligence": threat,
                "correlation": corr,
                "correlation_all": corr_all,
                "unified": unified,
                "browser": browser,
                "web_content": web,
                "ai_analysis": ai,
            },
            "observability": {"trace_id": trace_id},
        }
        status = (
            "PARTIAL"
            if ai.get("status") == "UNAVAILABLE"
            or corr_all.get("unavailable_sources", 0) > 0
            else "COMPLETED"
        )
        duration = round((time.perf_counter() - started) * 1000, 2)
        add_scan_event(
            scan_id, trace_id, "SCAN_COMPLETED", "pipeline",
            status=status, duration_ms=duration,
            metadata={
                "risk_score": risk.get("risk_score"),
                "confidence_score": risk.get("confidence_score"),
            },
        )
        update_scan(scan_id, status, result=result)
        log_event(
            "scan.completed",
            scan_id=scan_id,
            trace_id=trace_id,
            status=status,
            duration_ms=duration,
            risk_score=risk.get("risk_score"),
            confidence_score=risk.get("confidence_score"),
        )
    except (
        URLValidationError,
        ScanError,
        DomainAnalysisError,
        TLSAnalysisError,
        ThreatIntelError,
        BrowserScanError,
    ) as exc:
        duration = round((time.perf_counter() - started) * 1000, 2)
        add_scan_event(
            scan_id, trace_id, "SCAN_FAILED", "pipeline",
            status="FAILED", duration_ms=duration,
            metadata={
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        update_scan(scan_id, "FAILED", error=str(exc))
        log_event(
            "scan.failed",
            scan_id=scan_id,
            trace_id=trace_id,
            duration_ms=duration,
            error_type=type(exc).__name__,
        )
