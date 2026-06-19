"""
report_generator.py — Generates a professional PDF security assessment report.

Structure:
  1. Cover Page  (dark navy, "Agent Security Report" hero)
  2. Executive Summary  (two separate tables: vuln severity | simulation stats)
  3. Risk Summary (LLM narrative)
  4. Vulnerability Analysis — Table A: CVSS Scores
  5. Vulnerability Analysis — Table B: Attack Details
  6. Attack Simulation Results (per-vuln breakdown table)
  7. Proof of Concept — per-vulnerability payload walk-through + mitigation
  8. Recommendations
  9. Methodology
"""

import io
import math
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# XML escaping helper
# ---------------------------------------------------------------------------
# ReportLab parses Paragraph text as a tiny XML dialect — any '<' / '>' / '&'
# coming from user input, the LLM, payloads, or victim responses must be
# escaped or the whole report blows up with a "Parse error" mid-render.
# We also strip ASCII control chars that can crash the parser.

def xml_escape(text: object) -> str:
    s = str(text or "")
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Strip control chars except newline, tab
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', s)
    return s

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak, NextPageTemplate,
)
from reportlab.platypus.flowables import Flowable

# ---------------------------------------------------------------------------
# Brand palette
# ---------------------------------------------------------------------------
C_BG        = colors.HexColor("#0f172a")   # cover/header navy
C_BG2       = colors.HexColor("#1e293b")   # secondary dark
C_TEAL      = colors.HexColor("#06d6a0")   # primary accent
C_TEAL_DARK = colors.HexColor("#059669")   # darker teal for contrast
C_WHITE     = colors.white
C_SLATE     = colors.HexColor("#64748b")
C_SLATE_LT  = colors.HexColor("#94a3b8")
C_BORDER    = colors.HexColor("#e2e8f0")
C_ROW_ALT   = colors.HexColor("#f8fafc")
C_CRITICAL  = colors.HexColor("#dc2626")
C_HIGH      = colors.HexColor("#ea580c")
C_MEDIUM    = colors.HexColor("#d97706")
C_LOW       = colors.HexColor("#16a34a")
C_UNKNOWN   = colors.HexColor("#94a3b8")
C_SAFE_BG   = colors.HexColor("#f0fdf4")
C_FAIL_BG   = colors.HexColor("#fff7ed")
C_WARN_BG   = colors.HexColor("#fef3c7")

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _priority_color(priority: str) -> colors.Color:
    return {"CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
            "MEDIUM": C_MEDIUM, "LOW": C_LOW}.get(priority.upper(), C_UNKNOWN)


def _risk_color(score: float) -> colors.Color:
    if score < 0.01:  return C_LOW
    if score < 0.34:  return C_LOW
    if score < 0.67:  return C_MEDIUM
    return C_CRITICAL


def _risk_label(score: float) -> str:
    if score < 0.01:  return "SAFE"
    if score < 0.34:  return "LOW RISK"
    if score < 0.67:  return "MEDIUM RISK"
    return "HIGH RISK"


def _overall_risk_label(score: float) -> str:
    if score < 0.01:  return "SAFE"
    if score < 0.34:  return "LOW"
    if score < 0.67:  return "MEDIUM"
    return "HIGH"


def _get_mitigation(vuln_type: str) -> tuple[str, str]:
    """Return (short title, detailed recommendation) for a vulnerability type."""
    v = vuln_type.lower()
    MAP = [
        ("rce",                 "Sandbox all code execution",
         "Never pass LLM-generated strings directly to a shell or exec(). Use allowlists, "
         "sandboxed runtimes (e.g. gVisor), and validate every tool parameter against a strict "
         "JSON schema before execution."),
        ("sql injection",       "Use parameterised queries exclusively",
         "Replace all string-interpolated SQL with parameterised statements or ORM methods. "
         "Validate input types before they reach any database tool, and apply a read-only "
         "connection for retrieval operations."),
        ("ssrf",                "Restrict outbound network access with an allowlist",
         "Maintain an explicit allowlist of permitted outbound URLs/IPs. Block all RFC-1918 "
         "ranges and cloud metadata endpoints (169.254.169.254, fd00::/8) at the network layer."),
        ("prompt injection",    "Implement input sanitisation and instruction hierarchy",
         "Separate system instructions from user data using structured delimiters. Treat all "
         "user-supplied and externally retrieved content as untrusted — never allow it to modify "
         "the instruction prefix."),
        ("system prompt leak",  "Mark system prompt confidential and filter outputs",
         "Explicitly instruct the model never to repeat its system prompt. Apply an output "
         "filter that detects and redacts verbatim instruction leakage before returning responses."),
        ("pdf",                 "Sanitise document content before injection",
         "Strip embedded scripts and macros from PDFs before text extraction. Wrap extracted "
         "content in a clearly labelled, untrusted-data block so the model applies appropriate "
         "scepticism."),
        ("data exfil",          "Monitor and restrict outbound tool calls",
         "Log every outbound HTTP call made by agent tools. Alert on unexpected destinations "
         "and require human approval before sensitive data leaves the trust boundary."),
        ("multi-turn",          "Limit cross-turn instruction persistence",
         "Apply context summarisation that strips injected instructions across turns. Validate "
         "that high-privilege instructions in conversation history match authorised sources."),
        ("memory",              "Protect persistent memory writes with integrity checks",
         "Require cryptographic signatures or human-in-the-loop approval for writes to "
         "persistent agent memory. Treat all memory reads as potentially poisoned input."),
        ("mcp tool poisoning",  "Audit and pin MCP tool manifests",
         "Verify MCP tool descriptions against a trusted, version-pinned registry before "
         "loading. Treat unexpected changes to tool definitions as a security incident."),
        ("mcp missing auth",    "Enforce authentication on all MCP endpoints",
         "All MCP endpoints must require short-lived, signed authentication tokens. Reject "
         "unauthenticated connections at the transport layer, not the application layer."),
        ("mcp excessive",       "Apply least-privilege to MCP tool scopes",
         "Each MCP tool should expose only the minimum permissions it needs. Audit tool scopes "
         "on every deployment and remove unused capabilities."),
        ("mcp rug pull",        "Validate MCP tool integrity post-approval",
         "Re-verify tool manifests after any approval event. Treat any post-approval mutation "
         "of tool descriptions or parameters as a security violation."),
        ("mcp insecure",        "Enforce TLS and certificate pinning for MCP transport",
         "All MCP connections must use TLS 1.2+. Pin the server certificate in the agent "
         "runtime and refuse connections with expired or untrusted certificates."),
        ("mcp cross-agent",     "Restrict cross-agent tool invocation permissions",
         "Establish explicit trust levels between agents. Child agents must not inherit "
         "parent-agent permissions without explicit grant."),
        ("rag knowledge",       "Restrict write access to the knowledge base",
         "Require human review before any new document enters the shared vector store. "
         "Validate document provenance and apply per-tenant namespacing to prevent cross-tenant "
         "data leakage."),
        ("cross-tenant",        "Implement strict per-tenant vector store isolation",
         "Use separate ChromaDB collections per user or tenant. Never allow cross-tenant "
         "document retrieval, even for administrators."),
        ("context window",      "Cap retrieved chunk size and protect system prompt position",
         "Limit total tokens injected from RAG retrieval. Ensure the system prompt always "
         "occupies the leading token positions and cannot be overwritten by retrieved content."),
        ("embedding inversion", "Rate-limit similarity queries and monitor patterns",
         "Apply per-user query rate limits on the retrieval API. Monitor for query patterns "
         "consistent with embedding inversion or reconstruction attacks."),
        ("rag retrieval bypass","Validate retrieval results before injection",
         "Apply a secondary relevance filter after retrieval to detect and drop content that "
         "is semantically inconsistent with the user's authorised query."),
        ("access control",      "Enforce RBAC checks on every tool invocation",
         "Validate the caller's role and permissions before executing any privileged tool. "
         "Never rely on the model itself to perform authorisation decisions."),
    ]
    for key, title, detail in MAP:
        if key in v:
            return title, detail
    return "Review and harden the affected component", (
        f"Conduct a targeted security review of the '{vuln_type}' attack surface. "
        "Apply defence-in-depth: input validation, output filtering, and monitoring."
    )


# ---------------------------------------------------------------------------
# Shared styles
# ---------------------------------------------------------------------------

def _build_styles() -> dict:
    styles = {
        # ── Cover ──────────────────────────────────────────────────────────
        "cover_eyebrow": ParagraphStyle(
            "cover_eyebrow", fontName="Helvetica",
            fontSize=9, textColor=C_TEAL,
            alignment=TA_CENTER, spaceAfter=2, letterSpacing=2,
        ),
        "cover_title": ParagraphStyle(
            "cover_title", fontName="Helvetica-Bold",
            fontSize=34, textColor=C_WHITE,
            alignment=TA_CENTER, spaceAfter=4, leading=40,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub", fontName="Helvetica",
            fontSize=12, textColor=colors.HexColor("#cbd5e1"),
            alignment=TA_CENTER, spaceAfter=3,
        ),
        "cover_meta_label": ParagraphStyle(
            "cover_meta_label", fontName="Helvetica",
            fontSize=8, textColor=C_SLATE_LT,
            alignment=TA_RIGHT,
        ),
        "cover_meta_value": ParagraphStyle(
            "cover_meta_value", fontName="Helvetica-Bold",
            fontSize=8, textColor=C_WHITE,
            alignment=TA_LEFT,
        ),
        "cover_conf": ParagraphStyle(
            "cover_conf", fontName="Helvetica-Bold",
            fontSize=7, textColor=colors.HexColor("#475569"),
            alignment=TA_CENTER, letterSpacing=1.5,
        ),
        # ── Section headings ───────────────────────────────────────────────
        "section_title": ParagraphStyle(
            "section_title", fontName="Helvetica-Bold",
            fontSize=13, textColor=C_BG,
            spaceBefore=12, spaceAfter=4,
        ),
        "subsection_title": ParagraphStyle(
            "subsection_title", fontName="Helvetica-Bold",
            fontSize=10, textColor=C_BG2,
            spaceBefore=10, spaceAfter=3,
        ),
        # ── Body text ──────────────────────────────────────────────────────
        "body": ParagraphStyle(
            "body", fontName="Helvetica",
            fontSize=9, textColor=colors.HexColor("#1e293b"),
            spaceAfter=4, leading=14,
        ),
        "body_bold": ParagraphStyle(
            "body_bold", fontName="Helvetica-Bold",
            fontSize=9, textColor=colors.HexColor("#1e293b"),
            spaceAfter=3,
        ),
        "small": ParagraphStyle(
            "small", fontName="Helvetica",
            fontSize=8, textColor=C_SLATE,
            spaceAfter=2, leading=12,
        ),
        "small_italic": ParagraphStyle(
            "small_italic", fontName="Helvetica-Oblique",
            fontSize=8, textColor=C_SLATE,
            spaceAfter=2, leading=11,
        ),
        # ── Table internals ────────────────────────────────────────────────
        "table_header": ParagraphStyle(
            "table_header", fontName="Helvetica-Bold",
            fontSize=8, textColor=C_WHITE,
        ),
        "table_cell": ParagraphStyle(
            "table_cell", fontName="Helvetica",
            fontSize=8, textColor=colors.HexColor("#1e293b"),
            leading=11,
        ),
        "table_cell_bold": ParagraphStyle(
            "table_cell_bold", fontName="Helvetica-Bold",
            fontSize=8, textColor=colors.HexColor("#1e293b"),
        ),
        "mono": ParagraphStyle(
            "mono", fontName="Courier",
            fontSize=7.5, textColor=colors.HexColor("#1e293b"),
            leading=11, backColor=colors.HexColor("#f1f5f9"),
        ),
        # ── Page footer ────────────────────────────────────────────────────
        "footer": ParagraphStyle(
            "footer", fontName="Helvetica",
            fontSize=7, textColor=C_SLATE, alignment=TA_CENTER,
        ),
    }
    return styles


# ---------------------------------------------------------------------------
# Custom coloured rule
# ---------------------------------------------------------------------------

class ColoredRule(HRFlowable):
    def __init__(self, color=C_TEAL, width="100%", thickness=2, **kw):
        super().__init__(width=width, thickness=thickness, color=color,
                         spaceAfter=4, spaceBefore=2, **kw)


class ThinRule(HRFlowable):
    def __init__(self, color=C_BORDER, **kw):
        super().__init__(width="100%", thickness=0.5, color=color,
                         spaceAfter=3, spaceBefore=3, **kw)


# ---------------------------------------------------------------------------
# Document template  (Cover  +  Content page templates)
# ---------------------------------------------------------------------------

def _make_doc(buf: io.BytesIO, agent_id: str, scan_date: str) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=24 * mm,
        bottomMargin=20 * mm,
        title=f"Agent Security Report — {agent_id}",
        author="LLMTron",
        subject="AI Agent Security Assessment",
    )

    def _cover_page(canvas, doc):
        canvas.saveState()
        W, H = PAGE_W, PAGE_H

        # ── Full navy background ──
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)

        # ── Decorative diagonal stripe (top-right) ──
        canvas.setFillColor(colors.HexColor("#0d2240"))
        p = canvas.beginPath()
        p.moveTo(W * 0.55, H)
        p.lineTo(W,         H)
        p.lineTo(W,         H * 0.48)
        p.close()
        canvas.drawPath(p, fill=1, stroke=0)

        # ── Teal accent bar — top ──
        canvas.setFillColor(C_TEAL)
        canvas.rect(0, H - 6 * mm, W, 6 * mm, fill=1, stroke=0)

        # ── Thinner teal bar — bottom ──
        canvas.setFillColor(C_TEAL)
        canvas.rect(0, 0, W, 3 * mm, fill=1, stroke=0)

        # ── Dot-grid watermark (subtle) ──
        canvas.setFillColor(colors.HexColor("#1a2e4a"))
        dot_r  = 1.0
        spacing = 12 * mm
        cols = int(W / spacing) + 1
        rows = int(H / spacing) + 1
        for ci in range(cols):
            for ri in range(rows):
                canvas.circle(ci * spacing, ri * spacing, dot_r, fill=1, stroke=0)

        # ── Left vertical accent stripe ──
        canvas.setFillColor(C_TEAL_DARK)
        canvas.rect(0, 0, 4 * mm, H, fill=1, stroke=0)

        # ── Horizontal separator line ──
        canvas.setStrokeColor(colors.HexColor("#1e3a5f"))
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN + 4 * mm, H * 0.38, W - MARGIN, H * 0.38)

        canvas.restoreState()

    def _content_page(canvas, doc):
        canvas.saveState()
        # White background (prevents cover navy from bleeding into content pages)
        canvas.setFillColor(colors.white)
        canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        # Top separator
        canvas.setStrokeColor(C_TEAL)
        canvas.setLineWidth(1.5)
        canvas.line(MARGIN, PAGE_H - 14 * mm, PAGE_W - MARGIN, PAGE_H - 14 * mm)
        # Header text
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(C_BG)
        canvas.drawString(MARGIN, PAGE_H - 10.5 * mm, "LLMTron — Agent Security Report")
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(C_SLATE)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 10.5 * mm, f"{agent_id}  ·  {scan_date}")
        # Bottom separator + page number
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 13 * mm, PAGE_W - MARGIN, 13 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_SLATE)
        canvas.drawCentredString(PAGE_W / 2, 8 * mm, f"Page {doc.page}   ·   CONFIDENTIAL")
        canvas.restoreState()

    cover_frame   = Frame(0, 0, PAGE_W, PAGE_H, id="cover", showBoundary=0)
    content_frame = Frame(
        MARGIN, 18 * mm,
        PAGE_W - 2 * MARGIN, PAGE_H - 38 * mm,
        id="content", showBoundary=0,
    )
    doc.addPageTemplates([
        PageTemplate(id="Cover",   frames=[cover_frame],   onPage=_cover_page),
        PageTemplate(id="Content", frames=[content_frame], onPage=_content_page),
    ])
    return doc


# ---------------------------------------------------------------------------
# Section 1 — Cover
# ---------------------------------------------------------------------------

def _cover_section(styles, agent_id, scan_date, mode, overall_risk_score, duration_seconds):
    elems = [
        Spacer(1, 52 * mm),

        # Eyebrow label
        Paragraph("CONFIDENTIAL  ·  AUTHORIZED PERSONNEL ONLY", styles["cover_eyebrow"]),
        Spacer(1, 3 * mm),

        # Main title
        Paragraph("Agent Security Report", styles["cover_title"]),
        Spacer(1, 1 * mm),

        # Platform sub-title
        Paragraph("AI Agent Security Assessment by LLMTron", styles["cover_sub"]),
        Spacer(1, 10 * mm),

        # Separator
        HRFlowable(width="60%", thickness=1, color=C_TEAL,
                   spaceBefore=0, spaceAfter=6 * mm, hAlign="CENTER"),
    ]

    # ── Metadata grid ──
    meta_rows = [
        ["AGENT ID",      agent_id],
        ["SCAN MODE",     mode.upper()],
        ["REPORT DATE",   scan_date],
        ["DURATION",      f"{round(duration_seconds)}s" if duration_seconds else "—"],
    ]
    label_style = ParagraphStyle(
        "ml", fontName="Helvetica", fontSize=8,
        textColor=C_SLATE_LT, alignment=TA_RIGHT,
    )
    value_style = ParagraphStyle(
        "mv", fontName="Helvetica-Bold", fontSize=8,
        textColor=C_WHITE, alignment=TA_LEFT,
    )
    meta_data = [[Paragraph(k, label_style), Paragraph(v, value_style)]
                 for k, v in meta_rows]
    meta_tbl = Table(meta_data, colWidths=[42 * mm, 85 * mm], hAlign="CENTER")
    meta_tbl.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEAFTER",     (0, 0), (0, -1),  0.5, colors.HexColor("#1e3a5f")),
    ]))
    elems.append(meta_tbl)
    elems.append(Spacer(1, 10 * mm))

    # ── Confidentiality footer ──
    elems.append(Spacer(1, 18 * mm))
    elems.append(Paragraph(
        "THIS DOCUMENT CONTAINS SENSITIVE SECURITY FINDINGS.\n"
        "DO NOT DISTRIBUTE BEYOND THE INTENDED SECURITY TEAM.",
        styles["cover_conf"],
    ))

    return elems


# ---------------------------------------------------------------------------
# Section 2 — Executive Summary  (two separate tables)
# ---------------------------------------------------------------------------

def _exec_summary_section(
    styles, attack_plan, eval_summaries,
    overall_risk, total_tested, total_success, total_fail,
    duration_seconds,
):
    elems = [
        Paragraph("Executive Summary", styles["section_title"]),
        ColoredRule(),
        Spacer(1, 4),
    ]

    avail_w = PAGE_W - 2 * MARGIN
    col_w   = [avail_w * 0.58, avail_w * 0.42]

    # ── Table 1: Vulnerability severity breakdown ──
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ap in attack_plan:
        p = ap.get("priority", "LOW").upper()
        counts[p] = counts.get(p, 0) + 1

    elems.append(Paragraph("Vulnerability Severity Breakdown", styles["subsection_title"]))

    sev_data = [
        [Paragraph("Metric", styles["table_header"]),
         Paragraph("Count / Value", styles["table_header"])],
        ["Overall Risk Score",
         f"{round(overall_risk * 100)}%  —  {_overall_risk_label(overall_risk)}"],
        ["Attack Paths Identified", str(len(attack_plan))],
        ["  ▸  CRITICAL", str(counts["CRITICAL"])],
        ["  ▸  HIGH",     str(counts["HIGH"])],
        ["  ▸  MEDIUM",   str(counts["MEDIUM"])],
        ["  ▸  LOW",      str(counts["LOW"])],
        ["Scan Duration",
         f"{round(duration_seconds)}s" if duration_seconds else "—"],
    ]

    sev_tbl = Table(sev_data, colWidths=col_w)
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        # Colour risk value
        ("TEXTCOLOR",    (1, 1), (1, 1),   _risk_color(overall_risk)),
        ("FONTNAME",     (1, 1), (1, 1),   "Helvetica-Bold"),
        # Colour severity counts
        ("TEXTCOLOR",    (1, 3), (1, 3),   C_CRITICAL),
        ("FONTNAME",     (1, 3), (1, 3),   "Helvetica-Bold"),
        ("TEXTCOLOR",    (1, 4), (1, 4),   C_HIGH),
        ("FONTNAME",     (1, 4), (1, 4),   "Helvetica-Bold"),
        ("TEXTCOLOR",    (1, 5), (1, 5),   C_MEDIUM),
        ("FONTNAME",     (1, 5), (1, 5),   "Helvetica-Bold"),
        ("TEXTCOLOR",    (1, 6), (1, 6),   C_LOW),
        ("FONTNAME",     (1, 6), (1, 6),   "Helvetica-Bold"),
    ]))
    elems.append(sev_tbl)

    # ── Table 2: Simulation statistics ──
    elems.append(Spacer(1, 10))
    elems.append(Paragraph("Attack Simulation Statistics", styles["subsection_title"]))

    sim_data = [
        [Paragraph("Metric", styles["table_header"]),
         Paragraph("Value", styles["table_header"])],
        ["Total Payloads Tested", str(total_tested)],
        ["  ▸  Refused  (model defended)",  str(total_success)],
        ["  ▸  Complied  (model vulnerable)", str(total_fail)],
    ]

    sim_tbl = Table(sim_data, colWidths=col_w)
    sim_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        # Refused = green, Complied = red
        ("TEXTCOLOR",    (1, 2), (1, 2),   C_LOW),
        ("FONTNAME",     (1, 2), (1, 2),   "Helvetica-Bold"),
        ("TEXTCOLOR",    (1, 3), (1, 3),   C_CRITICAL),
        ("FONTNAME",     (1, 3), (1, 3),   "Helvetica-Bold"),
    ]))
    elems.append(sim_tbl)

    return elems


# ---------------------------------------------------------------------------
# Section 3 — Risk Summary
# ---------------------------------------------------------------------------

def _risk_summary_section(styles, risk_summary):
    return [
        Spacer(1, 6),
        Paragraph("Risk Summary", styles["section_title"]),
        ColoredRule(),
        Spacer(1, 4),
        Paragraph(xml_escape(risk_summary), styles["body"]),
    ]


# ---------------------------------------------------------------------------
# Section 4+5 — Vulnerability Analysis  (two separate tables)
# ---------------------------------------------------------------------------

def _vuln_analysis_section(styles, attack_plan):
    avail_w = PAGE_W - 2 * MARGIN
    elems = [
        PageBreak(),
        Paragraph("Vulnerability Analysis", styles["section_title"]),
        ColoredRule(),
        Spacer(1, 4),
        Paragraph(
            "The tables below detail each attack path identified during the analysis phase. "
            "Table A shows CVSS severity scores. Table B shows the corresponding attack details.",
            styles["small"],
        ),
        Spacer(1, 8),
    ]

    # ── Table A: CVSS Scores ──────────────────────────────────────────────
    elems.append(Paragraph("Table A — CVSS Severity Scores", styles["subsection_title"]))

    col_a = [avail_w * 0.48, avail_w * 0.17, avail_w * 0.18, avail_w * 0.17]
    header_a = [
        Paragraph("Vulnerability",  styles["table_header"]),
        Paragraph("Priority",       styles["table_header"]),
        Paragraph("CVSS Score",     styles["table_header"]),
        Paragraph("MAESTRO Layer",  styles["table_header"]),
    ]
    rows_a = [header_a]
    for ap in attack_plan:
        priority = ap.get("priority", "LOW").upper()
        severity = ap.get("severity", 0.0)
        rows_a.append([
            Paragraph(xml_escape(ap.get("vulnerability_type", "")), styles["table_cell"]),
            Paragraph(f"<b>{xml_escape(priority)}</b>", ParagraphStyle(
                "pri_a", fontName="Helvetica-Bold", fontSize=8,
                textColor=_priority_color(priority))),
            Paragraph(f"<b>{severity:.1f}</b>", ParagraphStyle(
                "sev_a", fontName="Helvetica-Bold", fontSize=8,
                textColor=_priority_color(priority))),
            Paragraph(xml_escape(ap.get("maestro_layer", "")), styles["table_cell"]),
        ])

    tbl_a = Table(rows_a, colWidths=col_a, repeatRows=1)
    tbl_a.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems.append(tbl_a)
    elems.append(Spacer(1, 14))

    # ── Table B: Attack Details ───────────────────────────────────────────
    elems.append(Paragraph("Table B — Attack Details", styles["subsection_title"]))

    col_b = [avail_w * 0.30, avail_w * 0.17, avail_w * 0.25, avail_w * 0.28]
    header_b = [
        Paragraph("Vulnerability",          styles["table_header"]),
        Paragraph("Injection Type",         styles["table_header"]),
        Paragraph("Target Asset",           styles["table_header"]),
        Paragraph("Exploit Strategy",       styles["table_header"]),
    ]
    rows_b = [header_b]
    for ap in attack_plan:
        rows_b.append([
            Paragraph(xml_escape(ap.get("vulnerability_type", "")), styles["table_cell"]),
            Paragraph(xml_escape(ap.get("injection_type", "")),     styles["table_cell"]),
            Paragraph(f"<b>{xml_escape(ap.get('target_asset',''))}</b>", styles["table_cell_bold"]),
            Paragraph(
                xml_escape(ap.get("exploit_strategy", "")[:180]),
                styles["table_cell"],
            ),
        ])

    tbl_b = Table(rows_b, colWidths=col_b, repeatRows=1)
    tbl_b.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(tbl_b)
    return elems


# ---------------------------------------------------------------------------
# Section 6 — Simulation Results table
# ---------------------------------------------------------------------------

def _simulation_section(styles, vuln_summaries, overall_risk,
                         total_tested, total_success, total_fail):
    avail_w = PAGE_W - 2 * MARGIN
    elems = [
        PageBreak(),
        Paragraph("Attack Simulation Results", styles["section_title"]),
        ColoredRule(),
        Spacer(1, 4),
        Paragraph(
            "Each vulnerability was tested with up to 5 adversarial payloads routed through a "
            "sandboxed harness (Direct, RAG, MCP, Memory, or PDF). "
            "Evaluation used a 4-layer pipeline: keyword matching → soft-fail regex → "
            "semantic similarity (all-MiniLM-L6-v2) → NLI cross-encoder (deberta-v3-small).",
            styles["small"],
        ),
        Spacer(1, 8),
    ]

    # Summary stat tiles
    w3 = avail_w / 3
    summary_data = [[
        Paragraph(
            f"<b><font size='16'>{total_tested}</font></b><br/>"
            "<font size='7' color='#64748b'>PAYLOADS TESTED</font>",
            ParagraphStyle("st", fontName="Helvetica-Bold", fontSize=9, alignment=TA_CENTER)),
        Paragraph(
            f"<b><font size='16' color='#16a34a'>{total_success}</font></b><br/>"
            "<font size='7' color='#64748b'>REFUSED  (SAFE)</font>",
            ParagraphStyle("st2", fontName="Helvetica-Bold", fontSize=9, alignment=TA_CENTER)),
        Paragraph(
            f"<b><font size='16' color='#dc2626'>{total_fail}</font></b><br/>"
            "<font size='7' color='#64748b'>COMPLIED  (VULNERABLE)</font>",
            ParagraphStyle("st3", fontName="Helvetica-Bold", fontSize=9, alignment=TA_CENTER)),
    ]]
    sum_tbl = Table(summary_data, colWidths=[w3] * 3)
    sum_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_ROW_ALT),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.5, C_BORDER),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    elems.append(sum_tbl)
    elems.append(Spacer(1, 12))

    # Per-vulnerability table
    col_w = [avail_w*0.33, avail_w*0.12, avail_w*0.15,
             avail_w*0.10, avail_w*0.10, avail_w*0.10, avail_w*0.10]
    header = [
        Paragraph("Vulnerability",   styles["table_header"]),
        Paragraph("Risk Score",      styles["table_header"]),
        Paragraph("Risk Level",      styles["table_header"]),
        Paragraph("Tested",          styles["table_header"]),
        Paragraph("Refused",         styles["table_header"]),
        Paragraph("Complied",        styles["table_header"]),
        Paragraph("Eval Method",     styles["table_header"]),
    ]

    active = [s for s in vuln_summaries if s.get("total", 0) > 0]
    active.sort(key=lambda s: s.get("risk_score", 0), reverse=True)

    rows = [header]
    for s in active:
        score   = s.get("risk_score", 0)
        pct     = round(score * 100)
        rc      = _risk_color(score)
        rl      = _risk_label(score)
        methods = [r.get("eval_method", "") for r in s.get("payload_results", [])]
        method  = max(set(methods), key=methods.count) if methods else "—"

        rows.append([
            Paragraph(s.get("vulnerability_type", ""), styles["table_cell"]),
            Paragraph(f"<b>{pct}%</b>", ParagraphStyle(
                "rs", fontName="Helvetica-Bold", fontSize=8, textColor=rc)),
            Paragraph(f"<b>{rl}</b>", ParagraphStyle(
                "rl", fontName="Helvetica-Bold", fontSize=8, textColor=rc)),
            Paragraph(str(s.get("total", 0)),         styles["table_cell"]),
            Paragraph(str(s.get("success_count", 0)), ParagraphStyle(
                "suc", fontName="Helvetica-Bold", fontSize=8, textColor=C_LOW)),
            Paragraph(str(s.get("fail_count", 0)),    ParagraphStyle(
                "fail", fontName="Helvetica-Bold", fontSize=8, textColor=C_CRITICAL)),
            Paragraph(method, styles["table_cell"]),
        ])

    tbl = Table(rows, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems.append(tbl)
    return elems


# ---------------------------------------------------------------------------
# Section 7 — Proof of Concept (per-vulnerability PoC cards)
# ---------------------------------------------------------------------------

def _poc_section(styles, attack_plan, vuln_summaries):
    """
    For every tested vulnerability: show
      - Risk header
      - Adversarial objective + exploit strategy
      - Table of payloads tested (text truncated, type, result)
      - Why failed (if any complied)
      - Mitigation
    """
    avail_w = PAGE_W - 2 * MARGIN

    # Build lookup maps
    plan_map = {ap.get("vulnerability_type", ""): ap for ap in attack_plan}
    active   = [s for s in vuln_summaries if s.get("total", 0) > 0]
    active.sort(key=lambda s: s.get("risk_score", 0), reverse=True)

    elems: list = [
        PageBreak(),
        Paragraph("Proof of Concept — Vulnerability Details", styles["section_title"]),
        ColoredRule(),
        Spacer(1, 4),
        Paragraph(
            "Each card below shows the payloads that were tested against the victim model, "
            "the evaluation outcome for each payload, and a targeted mitigation. "
            "FAIL = model complied with the attack (vulnerable). "
            "SUCCESS = model refused (defended). "
            "UNKNOWN = evaluator could not determine outcome.",
            styles["small"],
        ),
        Spacer(1, 10),
    ]

    RESULT_COLORS = {
        "FAIL":    C_CRITICAL,
        "SUCCESS": C_LOW,
        "UNKNOWN": C_UNKNOWN,
    }
    RESULT_LABEL = {
        "FAIL":    "FAIL — complied",
        "SUCCESS": "PASS — refused",
        "UNKNOWN": "UNKNOWN",
    }

    for s in active:
        vtype    = s.get("vulnerability_type", "Unknown")
        score    = s.get("risk_score", 0.0)
        pct      = round(score * 100)
        rc       = _risk_color(score)
        rl       = _risk_label(score)
        ap       = plan_map.get(vtype, {})
        results  = s.get("payload_results", [])
        mit_title, mit_detail = _get_mitigation(vtype)

        card_elems = []

        # ── Card header ──
        hdr_data = [[
            Paragraph(
                f"<b>{xml_escape(vtype)}</b>",
                ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE),
            ),
            Paragraph(
                f"<b>{pct}%  ·  {xml_escape(rl)}</b>",
                ParagraphStyle("phl", fontName="Helvetica-Bold", fontSize=9,
                               textColor=rc, alignment=TA_RIGHT),
            ),
        ]]
        hdr_tbl = Table(hdr_data, colWidths=[avail_w * 0.70, avail_w * 0.30])
        hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_BG),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        card_elems.append(hdr_tbl)

        # ── Context box: target + adversarial objective ──
        ctx_lines = []
        if ap.get("target_asset"):
            ctx_lines.append(f"<b>Target:</b>  {xml_escape(ap['target_asset'])}")
        if ap.get("adversarial_objective"):
            ctx_lines.append(f"<b>Adversarial Objective:</b>  {xml_escape(ap['adversarial_objective'])}")
        if ap.get("exploit_strategy"):
            ctx_lines.append(f"<b>Exploit Strategy:</b>  {xml_escape(ap['exploit_strategy'])}")
        if ap.get("atfaa_domain"):
            ctx_lines.append(f"<b>ATFAA Domain:</b>  {xml_escape(ap['atfaa_domain'])}")

        ctx_body = "<br/>".join(ctx_lines) if ctx_lines else "No additional context."
        ctx_para = Paragraph(ctx_body, ParagraphStyle(
            "ctx", fontName="Helvetica", fontSize=8,
            textColor=colors.HexColor("#1e293b"),
            backColor=colors.HexColor("#f8fafc"),
            leading=13, leftIndent=0, rightIndent=0,
        ))
        ctx_tbl = Table([[ctx_para]], colWidths=[avail_w])
        ctx_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        card_elems.append(ctx_tbl)

        # ── Payload test table  (2 rows per payload: payload row + response row) ──
        if results:
            # Columns: Payload | Type | Result | Eval Method
            p_col = [avail_w * 0.52, avail_w * 0.13, avail_w * 0.18, avail_w * 0.17]
            NUM_COLS = 4

            p_hdr = [
                Paragraph("Payload (truncated)",  styles["table_header"]),
                Paragraph("Type",                 styles["table_header"]),
                Paragraph("Result",               styles["table_header"]),
                Paragraph("Eval Method",          styles["table_header"]),
            ]
            p_rows = [p_hdr]
            style_extra = []   # extra TableStyle commands built while iterating

            for idx, r in enumerate(results):
                res          = r.get("result", "UNKNOWN")
                rcolor       = RESULT_COLORS.get(res, C_UNKNOWN)
                rlabel       = RESULT_LABEL.get(res, res)
                payload_text = r.get("payload", "")
                response_raw = r.get("victim_response", "") or ""

                # ── Truncate payload to 220 chars ──
                p_display = (payload_text[:220] + "…") if len(payload_text) > 220 else payload_text

                # ── Truncate response to 350 chars; keep the most revealing part ──
                if len(response_raw) > 350:
                    r_display = response_raw[:350] + "…"
                else:
                    r_display = response_raw or "(no response recorded)"

                # Row A — payload details
                p_rows.append([
                    Paragraph(xml_escape(p_display), ParagraphStyle(
                        "pt", fontName="Courier", fontSize=7,
                        textColor=colors.HexColor("#1e293b"), leading=10,
                    )),
                    Paragraph(xml_escape(r.get("payload_type", "")), styles["table_cell"]),
                    Paragraph(f"<b>{xml_escape(rlabel)}</b>", ParagraphStyle(
                        "pr", fontName="Helvetica-Bold", fontSize=7.5,
                        textColor=rcolor,
                    )),
                    Paragraph(xml_escape(r.get("eval_method", "")), styles["table_cell"]),
                ])

                # Row B — agent response (spans all columns)
                if res == "FAIL":
                    resp_bg    = colors.HexColor("#fff5f5")
                    resp_color = colors.HexColor("#991b1b")
                    prefix     = "⚠ Agent Response (complied):"
                elif res == "SUCCESS":
                    resp_bg    = colors.HexColor("#f0fdf4")
                    resp_color = colors.HexColor("#166534")
                    prefix     = "✓ Agent Response (refused):"
                else:
                    resp_bg    = colors.HexColor("#f8fafc")
                    resp_color = C_SLATE
                    prefix     = "Agent Response:"

                resp_para = Paragraph(
                    f'<font name="Helvetica-Bold" size="7" color="{resp_color.hexval()}">'
                    f'{xml_escape(prefix)}</font>  '
                    f'<font name="Helvetica" size="7.5">{xml_escape(r_display)}</font>',
                    ParagraphStyle(
                        "rp", fontName="Helvetica", fontSize=7.5,
                        textColor=colors.HexColor("#1e293b"), leading=11,
                    ),
                )
                # Pad the other 3 cells with empty strings so ReportLab row has right length
                p_rows.append([resp_para, "", "", ""])

                # Build row indices (header is row 0, so payload A is at row base, response B is base+1)
                row_a = 1 + idx * 2       # payload row
                row_b = row_a + 1         # response row

                # Span response row across all columns
                style_extra.append(("SPAN",       (0, row_b), (NUM_COLS - 1, row_b)))
                style_extra.append(("BACKGROUND", (0, row_b), (-1, row_b), resp_bg))
                style_extra.append(("LEFTPADDING", (0, row_b), (-1, row_b), 10))
                style_extra.append(("TOPPADDING",    (0, row_b), (-1, row_b), 4))
                style_extra.append(("BOTTOMPADDING", (0, row_b), (-1, row_b), 5))

                # Tint the payload row for FAIL
                if res == "FAIL":
                    style_extra.append(
                        ("BACKGROUND", (0, row_a), (-1, row_a), colors.HexColor("#fff8f8"))
                    )

            p_tbl = Table(p_rows, colWidths=p_col, repeatRows=1)
            base_style = [
                ("BACKGROUND",    (0, 0), (-1, 0),  C_BG),
                ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
                ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]
            p_tbl.setStyle(TableStyle(base_style + style_extra))
            card_elems.append(p_tbl)
        else:
            card_elems.append(Paragraph(
                "No payload results recorded for this vulnerability.",
                styles["small_italic"],
            ))

        # ── Why it failed (only if there are failures) ──
        fail_count = s.get("fail_count", 0)
        if fail_count > 0:
            why_lines = []
            if ap.get("exploit_strategy"):
                why_lines.append(
                    f"The model complied with {fail_count} of {s.get('total',0)} tested payloads. "
                    f"The exploit strategy '<i>{xml_escape(ap['exploit_strategy'])}</i>' was effective because "
                    "the model did not detect the adversarial framing and followed the injected "
                    "instruction."
                )
            else:
                why_lines.append(
                    f"The model complied with {fail_count} of {s.get('total',0)} tested payloads, "
                    "indicating insufficient defence against this attack vector."
                )
            why_para = Paragraph(" ".join(why_lines), ParagraphStyle(
                "why", fontName="Helvetica", fontSize=8,
                textColor=colors.HexColor("#7f1d1d"),
                backColor=colors.HexColor("#fff5f5"),
                leading=12, borderPad=4,
            ))
            why_tbl = Table([[why_para]], colWidths=[avail_w])
            why_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#fff5f5")),
                ("BOX",           (0, 0), (-1, -1), 0.8, C_CRITICAL),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            card_elems.append(why_tbl)

        # ── Mitigation box ──
        mit_para = Paragraph(
            f"<b>Mitigation: {mit_title}</b><br/>{mit_detail}",
            ParagraphStyle(
                "mit", fontName="Helvetica", fontSize=8,
                textColor=colors.HexColor("#14532d"),
                leading=12,
            ),
        )
        mit_tbl = Table([[mit_para]], colWidths=[avail_w])
        mit_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
            ("BOX",           (0, 0), (-1, -1), 0.8, C_LOW),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        card_elems.append(mit_tbl)
        card_elems.append(Spacer(1, 10))

        elems.append(KeepTogether(card_elems[:4]))   # keep header+ctx+first few rows together
        elems.extend(card_elems[4:])                 # rest can flow freely

    return elems


# ---------------------------------------------------------------------------
# Section 8 — Recommendations
# ---------------------------------------------------------------------------

def _recommendations_section(styles, attack_plan, vuln_summaries):
    score_map = {s["vulnerability_type"]: s.get("risk_score", 0)
                 for s in vuln_summaries if s.get("total", 0) > 0}

    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    matched = []
    seen_titles: set = set()
    for ap in attack_plan:
        vtype    = ap.get("vulnerability_type", "")
        score    = score_map.get(vtype, 0)
        priority = ap.get("priority", "LOW")
        title, detail = _get_mitigation(vtype)
        if title not in seen_titles:
            seen_titles.add(title)
            matched.append((score, title, detail, priority))

    matched.sort(key=lambda x: (-x[0], priority_order.get(x[3].upper(), 3)))

    elems = [
        PageBreak(),
        Paragraph("Recommendations", styles["section_title"]),
        ColoredRule(),
        Spacer(1, 4),
        Paragraph(
            "The following recommendations are ordered by simulated risk score (highest first). "
            "Items marked HIGH or CRITICAL should be addressed before the next production deployment.",
            styles["small"],
        ),
        Spacer(1, 8),
    ]

    for i, (score, title, detail, priority) in enumerate(matched, 1):
        rc = _risk_color(score)
        badge = Paragraph(
            f"<b>{priority}</b>",
            ParagraphStyle("rb", fontName="Helvetica-Bold", fontSize=7.5,
                           textColor=_priority_color(priority)),
        )
        elems.append(KeepTogether([
            Paragraph(
                f"{i}.  {title}",
                ParagraphStyle("rt", fontName="Helvetica-Bold", fontSize=9,
                               textColor=C_BG, spaceAfter=2),
            ),
            Paragraph(detail, styles["body"]),
            Spacer(1, 4),
        ]))

    if not matched:
        elems.append(Paragraph(
            "No specific recommendations could be derived from the current findings.",
            styles["body"],
        ))
    return elems


# ---------------------------------------------------------------------------
# Section 9 — Methodology
# ---------------------------------------------------------------------------

def _methodology_section(styles):
    elems = [
        PageBreak(),
        Paragraph("Methodology", styles["section_title"]),
        ColoredRule(),
        Spacer(1, 4),
    ]

    sections = [
        ("MAESTRO Framework",
         "Each vulnerability is mapped to one of six architectural layers: Foundation Model, "
         "Data Operations, Agent Framework, Infrastructure, Security & Compliance, and Agent Ecosystem. "
         "This decomposition identifies where in the system stack the vulnerability resides and "
         "which team owns remediation."),
        ("ATFAA Behavioural Threat Framework",
         "Threats are classified by behavioural domain: Cognitive Architecture (goal drift), "
         "Temporal Persistence (memory poisoning), Operational Execution (tool abuse), "
         "Trust Boundary Violation (untrusted input processing), and Governance Circumvention "
         "(bypassing human oversight)."),
        ("OWASP LLM Top 10",
         "All identified vulnerabilities are cross-referenced against the OWASP Top 10 for LLMs "
         "(LLM01–LLM10), including Prompt Injection, Insecure Output Handling, Model Denial of Service, "
         "Sensitive Information Disclosure, Insecure Plugin Design, and Excessive Agency."),
        ("CVSS v3.1 Severity Scoring",
         "Each vulnerability is scored using the CVSS v3.1 formula with metrics inferred from the "
         "vulnerability type: Attack Vector, Attack Complexity, Privileges Required, User Interaction, "
         "Scope, and CIA Impact triad. Scores ≥9.0 = CRITICAL, ≥7.0 = HIGH, ≥5.0 = MEDIUM, <5.0 = LOW."),
        ("4-Layer Evaluation Pipeline",
         "Layer 1: Rule-based keyword matching for explicit refusals and harmful compliance signals. "
         "Layer 1.5: Domain-specific soft-fail regex (hypothetical framing, DAN mode, hedged compliance). "
         "Layer 2: Cosine similarity against refusal/compliance centroids via all-MiniLM-L6-v2 "
         "(auto-calibrated threshold). "
         "Layer 3: NLI cross-encoder (cross-encoder/nli-deberta-v3-small) scoring the hypothesis "
         "'The AI model refused the adversarial prompt.' "
         "Fallback: LLM judge (llama3)."),
        ("Sandboxed Attack Harnesses",
         "Payloads are delivered through realistic attack surfaces: RAGHarness poisons an in-memory "
         "ChromaDB vector store; MCPHarness injects via a mock tool response; MemoryHarness injects "
         "via poisoned conversation history; PDFHarness embeds the payload in crafted extracted text; "
         "DirectHarness delivers the payload as a direct user prompt."),
    ]

    for title, body in sections:
        elems.append(KeepTogether([
            Paragraph(title, styles["body_bold"]),
            Paragraph(body,  styles["body"]),
            Spacer(1, 6),
        ]))

    return elems


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_pdf_report(
    agent_id: str,
    risk_summary: str,
    attack_plan: List[Dict],
    vuln_summaries: List[Dict],
    overall_risk_score: float,
    total_tested: int,
    total_success: int,
    total_fail: int,
    total_unknown: int,
    mode: str = "quick",
    duration_seconds: Optional[float] = None,
) -> bytes:
    """Generate the full PDF report and return raw bytes."""
    buf       = io.BytesIO()
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M UTC")
    styles    = _build_styles()
    doc       = _make_doc(buf, agent_id, scan_date)
    dur       = duration_seconds or 0.0

    story: list = []

    # 1 — Cover  (dark background template)
    story += _cover_section(styles, agent_id, scan_date, mode, overall_risk_score, dur)

    # Switch template BEFORE the break so the very next page uses Content (white)
    story.append(NextPageTemplate("Content"))
    story.append(PageBreak())

    # 2 — Executive Summary (two separate tables)
    story += _exec_summary_section(
        styles, attack_plan, vuln_summaries,
        overall_risk_score, total_tested, total_success, total_fail, dur,
    )

    # 3 — Risk Summary
    story += _risk_summary_section(styles, risk_summary)

    # 4+5 — Vulnerability Analysis (Table A: CVSS, Table B: Details)
    story += _vuln_analysis_section(styles, attack_plan)

    # 6 — Simulation Results
    story += _simulation_section(
        styles, vuln_summaries,
        overall_risk_score, total_tested, total_success, total_fail,
    )

    # 7 — Proof of Concept (per-vulnerability payload walk-through)
    story += _poc_section(styles, attack_plan, vuln_summaries)

    # 8 — Recommendations
    story += _recommendations_section(styles, attack_plan, vuln_summaries)

    # 9 — Methodology
    story += _methodology_section(styles)

    doc.build(story)
    return buf.getvalue()
