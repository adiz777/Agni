"""
Agni (अग्नि) - Multi-Format Report Exporter
File: backend/app/services/exporter.py
"""

from __future__ import annotations

import csv
import html
import io
import json
import logging
from datetime import UTC, datetime

from sqlalchemy.orm import Session, joinedload

from app.models.incident import IncidentModel

logger = logging.getLogger("agni.services.exporter")


# Original Agni Fire-Shield Scalable Vector Graphic (SVG)
AGNI_LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="48" height="48" fill="none">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1e293b"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>
    <linearGradient id="flameGrad" x1="0%" y1="100%" x2="50%" y2="0%">
      <stop offset="0%" stop-color="#ef4444"/>
      <stop offset="50%" stop-color="#f97316"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
  </defs>
  <!-- Hexagonal Shield Outline -->
  <polygon points="50,5 90,25 90,70 50,95 10,70 10,25" stroke="#06b6d4" stroke-width="3" fill="url(#shieldGrad)"/>
  <!-- Agni Sacred Flame Symbol -->
  <path d="M 50,20 C 58,35 68,45 64,62 C 60,78 40,78 36,62 C 32,48 44,38 50,20 Z" fill="url(#flameGrad)" opacity="0.95"/>
  <path d="M 50,38 C 54,46 58,52 56,60 C 54,68 46,68 44,60 C 42,52 47,46 50,38 Z" fill="#fbbf24"/>
  <!-- Central Radar Core Node -->
  <circle cx="50" cy="58" r="4" fill="#ffffff"/>
</svg>"""


class ReportExporter:
    """Exports security incident reports to JSON, CSV, and standalone styled HTML."""

    @classmethod
    def query_incidents(
        cls,
        db: Session,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        severity: str | None = None,
        status: str | None = None,
        include_sample: bool = False,
    ) -> list[IncidentModel]:
        """Queries incidents matching filter criteria with alerts and notes eagerly loaded."""
        query = (
            db.query(IncidentModel)
            .options(joinedload(IncidentModel.alerts), joinedload(IncidentModel.notes))
            .order_by(IncidentModel.first_seen.desc())
        )

        if not include_sample:
            query = query.filter(IncidentModel.is_sample.is_(False))

        if start_time:
            query = query.filter(IncidentModel.first_seen >= start_time)
        if end_time:
            query = query.filter(IncidentModel.last_seen <= end_time)
        if severity:
            query = query.filter(IncidentModel.severity.ilike(severity))
        if status:
            query = query.filter(IncidentModel.status.ilike(status))

        return query.all()

    @classmethod
    def export(
        cls,
        db: Session,
        export_format: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        severity: str | None = None,
        status: str | None = None,
        include_sample: bool = False,
    ) -> tuple[str, str, bytes]:
        """
        Generates and returns (content_type, filename, raw_bytes).
        Supported formats: 'json', 'csv', 'html'.
        """
        incidents = cls.query_incidents(
            db=db,
            start_time=start_time,
            end_time=end_time,
            severity=severity,
            status=status,
            include_sample=include_sample,
        )

        timestamp_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        fmt = export_format.strip().lower()

        if fmt == "json":
            filename = f"agni_incident_report_{timestamp_str}.json"
            content_type = "application/json"
            raw_bytes = cls._generate_json(incidents, include_sample)
        elif fmt == "csv":
            filename = f"agni_incident_report_{timestamp_str}.csv"
            content_type = "text/csv; charset=utf-8"
            raw_bytes = cls._generate_csv(incidents)
        elif fmt == "html":
            filename = f"agni_incident_report_{timestamp_str}.html"
            content_type = "text/html; charset=utf-8"
            raw_bytes = cls._generate_html(incidents, include_sample)
        else:
            raise ValueError(f"Unsupported report export format: '{export_format}'")

        return content_type, filename, raw_bytes

    @classmethod
    def _generate_json(cls, incidents: list[IncidentModel], include_sample: bool) -> bytes:
        stats = cls._compute_stats(incidents)
        data = {
            "report_title": "Agni (अग्नि) Incident & Threat Investigation Report",
            "generated_at": datetime.now(UTC).isoformat(),
            "generator_version": "1.0.0",
            "include_sample_data": include_sample,
            "summary_statistics": stats,
            "incidents": [
                {
                    "id": inc.id,
                    "title": inc.title,
                    "rule_id": inc.rule_id,
                    "severity": inc.severity,
                    "priority": inc.priority,
                    "status": inc.status,
                    "entity_key": inc.entity_key,
                    "first_seen": inc.first_seen.isoformat() if inc.first_seen else None,
                    "last_seen": inc.last_seen.isoformat() if inc.last_seen else None,
                    "event_count": inc.event_count,
                    "summary": inc.summary,
                    "mitre_attack": inc.mitre_attack,
                    "assigned_analyst": inc.assigned_analyst,
                    "is_sample": inc.is_sample,
                    "alerts": [
                        {
                            "id": a.id,
                            "rule_id": a.rule_id,
                            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                            "severity": a.severity,
                            "explanation": a.explanation,
                            "triggering_event_id": a.triggering_event_id,
                            "match_details": a.match_details,
                        }
                        for a in inc.alerts
                    ],
                    "notes": [
                        {
                            "id": n.id,
                            "author": n.author,
                            "created_at": n.created_at.isoformat() if n.created_at else None,
                            "content": n.content,
                        }
                        for n in inc.notes
                    ],
                }
                for inc in incidents
            ],
        }
        return json.dumps(data, indent=2).encode("utf-8")

    @classmethod
    def _generate_csv(cls, incidents: list[IncidentModel]) -> bytes:
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        writer.writerow([
            "Incident ID",
            "Title",
            "Severity",
            "Priority",
            "Status",
            "Rule ID",
            "MITRE ATT&CK",
            "Entity Key",
            "Event Count",
            "First Seen (UTC)",
            "Last Seen (UTC)",
            "Assigned Analyst",
            "Is Sample",
            "Summary",
        ])

        for inc in incidents:
            writer.writerow([
                inc.id,
                inc.title,
                inc.severity,
                inc.priority,
                inc.status,
                inc.rule_id,
                inc.mitre_attack or "N/A",
                inc.entity_key,
                inc.event_count,
                inc.first_seen.isoformat() if inc.first_seen else "",
                inc.last_seen.isoformat() if inc.last_seen else "",
                inc.assigned_analyst or "Unassigned",
                "True" if inc.is_sample else "False",
                inc.summary,
            ])

        return output.getvalue().encode("utf-8")

    @classmethod
    def _generate_html(cls, incidents: list[IncidentModel], include_sample: bool) -> bytes:
        stats = cls._compute_stats(incidents)
        now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        def get_sev_color(sev: str) -> tuple[str, str]:
            s = sev.lower()
            if s == "critical":
                return "#ef4444", "#450a0a"
            if s == "high":
                return "#f97316", "#431407"
            if s == "medium":
                return "#fbbf24", "#451a03"
            if s == "low":
                return "#3b82f6", "#172554"
            return "#94a3b8", "#0f172a"

        table_rows = []
        for inc in incidents:
            fg, bg = get_sev_color(inc.severity)
            first_seen_str = inc.first_seen.strftime('%Y-%m-%d %H:%M:%S') if inc.first_seen else 'N/A'
            row_html = f"""
            <tr>
              <td><span style="font-family: monospace; color: #06b6d4;">{html.escape(inc.id[:8])}</span></td>
              <td><strong>{html.escape(inc.title)}</strong></td>
              <td><span class="badge" style="color: {fg}; background: {bg}; border: 1px solid {fg};">{html.escape(inc.severity)}</span></td>
              <td><span class="badge badge-status">{html.escape(inc.status)}</span></td>
              <td><span style="color: #cbd5e1; font-size: 0.85rem;">{first_seen_str}</span></td>
              <td><span style="color: #38bdf8;">{inc.event_count}</span></td>
              <td><span style="font-family: monospace; font-size: 0.8rem; color: #a5b4fc;">{html.escape(inc.mitre_attack or 'None')}</span></td>
            </tr>
            """
            table_rows.append(row_html)

        detail_cards = []
        for inc in incidents:
            fg, bg = get_sev_color(inc.severity)
            notes_html = ""
            if inc.notes:
                notes_items = "".join(
                    f"<div class='note-item'><span class='note-author'>{html.escape(n.author)}</span> ({n.created_at.strftime('%Y-%m-%d %H:%M:%S') if n.created_at else ''}): {html.escape(n.content)}</div>"
                    for n in inc.notes
                )
                notes_html = f"<div class='incident-notes-section'><h4>Analyst Notes</h4>{notes_items}</div>"

            alerts_preview = ""
            if inc.alerts:
                alerts_items = "".join(
                    f"<li><span class='code-snippet'>{html.escape(a.explanation)}</span> (Event ID: {html.escape(a.triggering_event_id or 'N/A')})</li>"
                    for a in inc.alerts[:5]
                )
                alerts_preview = f"<div class='alerts-preview'><h4>Triggering Alert Details</h4><ul>{alerts_items}</ul></div>"

            first_seen_dt = inc.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC') if inc.first_seen else 'N/A'
            last_seen_dt = inc.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC') if inc.last_seen else 'N/A'

            card_html = f"""
            <div class="incident-card">
              <div class="incident-card-header">
                <div>
                  <span class="badge" style="color: {fg}; background: {bg}; border: 1px solid {fg};">{html.escape(inc.severity)}</span>
                  <span class="incident-id">ID: {html.escape(inc.id)}</span>
                  <h3 class="incident-title">{html.escape(inc.title)}</h3>
                </div>
                <div style="text-align: right;">
                  <span class="badge badge-status">{html.escape(inc.status)}</span>
                  <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">Priority: {html.escape(inc.priority)}</div>
                </div>
              </div>
              <p class="incident-summary">{html.escape(inc.summary)}</p>
              <div class="incident-meta-grid">
                <div><span class="meta-label">Rule ID:</span> {html.escape(inc.rule_id)}</div>
                <div><span class="meta-label">MITRE ATT&CK:</span> <span class="tag-mitre">{html.escape(inc.mitre_attack or 'None')}</span></div>
                <div><span class="meta-label">Entity Key:</span> <span style="font-family: monospace;">{html.escape(inc.entity_key)}</span></div>
                <div><span class="meta-label">Event Count:</span> {inc.event_count}</div>
                <div><span class="meta-label">First Seen:</span> {first_seen_dt}</div>
                <div><span class="meta-label">Last Seen:</span> {last_seen_dt}</div>
              </div>
              {alerts_preview}
              {notes_html}
            </div>
            """
            detail_cards.append(card_html)

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agni SOC Threat Investigation Report</title>
  <style>
    /* Agni SOC Dark Design System */
    :root {{
      --bg-canvas: #0a0f1d;
      --bg-panel: #0f172a;
      --bg-card: #1e293b;
      --border-color: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent-cyan: #06b6d4;
      --accent-blue: #3b82f6;
      --color-critical: #ef4444;
      --color-high: #f97316;
      --color-medium: #fbbf24;
      --color-low: #3b82f6;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg-canvas);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
      padding: 32px 24px;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header-banner {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: var(--bg-panel);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 24px 32px;
      margin-bottom: 28px;
    }}
    .header-title-box {{ display: flex; align-items: center; gap: 20px; }}
    .logo-container {{ display: flex; align-items: center; }}
    h1 {{ font-size: 1.8rem; font-weight: 700; color: #ffffff; }}
    .subtitle {{ color: var(--accent-cyan); font-size: 0.95rem; margin-top: 4px; }}
    .header-meta {{ text-align: right; font-size: 0.85rem; color: var(--text-muted); }}

    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }}
    .kpi-card {{
      background: var(--bg-panel);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 18px;
      text-align: center;
    }}
    .kpi-value {{ font-size: 2.2rem; font-weight: 800; line-height: 1.1; margin-bottom: 4px; }}
    .kpi-label {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }}

    .table-container {{
      background: var(--bg-panel);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      overflow-x: auto;
      margin-bottom: 36px;
    }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; }}
    th {{
      background: #1e293b;
      color: #cbd5e1;
      padding: 14px 16px;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border-color);
    }}
    td {{
      padding: 14px 16px;
      border-bottom: 1px solid #1e293b;
      font-size: 0.9rem;
    }}
    tr:hover td {{ background: #131c31; }}

    .badge {{
      display: inline-block;
      padding: 3px 10px;
      font-size: 0.75rem;
      font-weight: 700;
      border-radius: 9999px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .badge-status {{
      background: #1e293b;
      color: #38bdf8;
      border: 1px solid #38bdf8;
    }}
    .tag-mitre {{
      display: inline-block;
      background: #312e81;
      color: #c7d2fe;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
    }}

    .section-heading {{
      font-size: 1.4rem;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 16px;
      border-left: 4px solid var(--accent-cyan);
      padding-left: 12px;
    }}
    .incident-card {{
      background: var(--bg-panel);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 22px;
      margin-bottom: 20px;
    }}
    .incident-card-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
    }}
    .incident-id {{ font-family: monospace; font-size: 0.8rem; color: var(--text-muted); margin-left: 8px; }}
    .incident-title {{ font-size: 1.25rem; font-weight: 700; color: #ffffff; margin-top: 6px; }}
    .incident-summary {{ color: #cbd5e1; margin-bottom: 14px; font-size: 0.95rem; }}
    .incident-meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
      background: #090e1a;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 12px 16px;
      font-size: 0.85rem;
      margin-bottom: 14px;
    }}
    .meta-label {{ color: var(--text-muted); font-weight: 600; }}
    .alerts-preview {{
      margin-top: 14px;
      padding: 12px 16px;
      background: #111827;
      border-left: 3px solid var(--accent-blue);
      border-radius: 4px;
    }}
    .alerts-preview h4, .incident-notes-section h4 {{
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #93c5fd;
      margin-bottom: 8px;
    }}
    .alerts-preview ul {{ margin-left: 20px; font-size: 0.85rem; color: #cbd5e1; }}
    .code-snippet {{ font-family: monospace; color: #facc15; }}
    .incident-notes-section {{
      margin-top: 14px;
      padding: 12px 16px;
      background: #1e1b4b;
      border-left: 3px solid #818cf8;
      border-radius: 4px;
    }}
    .note-item {{ font-size: 0.85rem; color: #e0e7ff; margin-top: 4px; }}
    .note-author {{ font-weight: 700; color: #a5b4fc; }}

    @media print {{
      body {{ background: #ffffff !important; color: #000000 !important; padding: 0 !important; }}
      .header-banner, .kpi-card, .table-container, .incident-card {{
        background: #ffffff !important;
        border: 1px solid #cccccc !important;
        color: #000000 !important;
        page-break-inside: avoid;
      }}
      th {{ background: #f1f5f9 !important; color: #000000 !important; }}
      h1, .incident-title, .section-heading {{ color: #000000 !important; }}
      .kpi-value {{ color: #000000 !important; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header-banner">
      <div class="header-title-box">
        <div class="logo-container">{AGNI_LOGO_SVG}</div>
        <div>
          <h1>Agni (अग्नि) Threat Investigation Report</h1>
          <div class="subtitle">Varuna Detection Engine & Incident Correlator</div>
        </div>
      </div>
      <div class="header-meta">
        <div><strong>Generated:</strong> {now_str}</div>
        <div><strong>Classification:</strong> RESTRICTED / TLP:AMBER</div>
        <div><strong>Total Incidents:</strong> {stats['total_incidents']}</div>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-value" style="color: var(--color-critical);">{stats['critical_count']}</div>
        <div class="kpi-label">Critical Threat</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value" style="color: var(--color-high);">{stats['high_count']}</div>
        <div class="kpi-label">High Severity</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value" style="color: var(--color-medium);">{stats['medium_count']}</div>
        <div class="kpi-label">Medium Severity</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value" style="color: var(--color-low);">{stats['low_count']}</div>
        <div class="kpi-label">Low / Info</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value" style="color: var(--accent-cyan);">{stats['open_incidents']}</div>
        <div class="kpi-label">Open / Active</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value" style="color: #34d399;">{stats['resolved_incidents']}</div>
        <div class="kpi-label">Resolved</div>
      </div>
    </div>

    <h2 class="section-heading">Incident Inventory</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Severity</th>
            <th>Status</th>
            <th>First Seen</th>
            <th>Events</th>
            <th>MITRE ATT&CK</th>
          </tr>
        </thead>
        <tbody>
          {"".join(table_rows) if table_rows else "<tr><td colspan='7' style='text-align: center; color: #94a3b8;'>No incidents found matching query criteria.</td></tr>"}
        </tbody>
      </table>
    </div>

    <h2 class="section-heading">Incident Investigation Dossiers</h2>
    {"".join(detail_cards) if detail_cards else "<p style='color: #94a3b8;'>No incident dossiers to display.</p>"}
  </div>
</body>
</html>"""
        return html_doc.encode("utf-8")

    @classmethod
    def _compute_stats(cls, incidents: list[IncidentModel]) -> dict[str, int]:
        total = len(incidents)
        critical = sum(1 for i in incidents if i.severity.lower() == "critical")
        high = sum(1 for i in incidents if i.severity.lower() == "high")
        medium = sum(1 for i in incidents if i.severity.lower() == "medium")
        low = sum(1 for i in incidents if i.severity.lower() in ("low", "informational"))
        open_count = sum(1 for i in incidents if i.status.lower() in ("new", "triaged", "in progress"))
        resolved = sum(1 for i in incidents if i.status.lower() == "resolved")
        false_positives = sum(1 for i in incidents if i.status.lower() == "false positive")

        return {
            "total_incidents": total,
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low,
            "open_incidents": open_count,
            "resolved_incidents": resolved,
            "false_positives": false_positives,
        }
