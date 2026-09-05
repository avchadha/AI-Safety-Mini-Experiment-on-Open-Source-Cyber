from __future__ import annotations

import html
import json
from pathlib import Path

from ..utils import atomic_write_text, read_jsonl


def render_timeline(data_root: Path, episode_id: str) -> Path:
    episode_dir = data_root / "episodes" / episode_id
    events = read_jsonl(episode_dir / "public_events.jsonl")
    truth = json.loads((episode_dir / "ground_truth.json").read_text(encoding="utf-8"))
    predictions = []
    for path in sorted((data_root / "predictions").glob(f"*/{episode_id}.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        predictions.append(
            (value["defender_id"], value["parsed_output"]["attack_probability"], value["parsed_output"]["evidence_event_ids"])
        )
    first_violation = truth.get("first_policy_violation_event_id")
    success = truth.get("success_event_id")
    rows = []
    for event in events:
        markers = []
        if event["event_id"] == first_violation:
            markers.append("policy violation")
        if event["event_id"] == success:
            markers.append("attack success")
        rows.append(
            "<tr>"
            f"<td>{event['sequence']}</td>"
            f"<td><code>{html.escape(event['event_id'])}</code></td>"
            f"<td>{html.escape(event['method'])}</td>"
            f"<td><code>{html.escape(event['path'])}</code></td>"
            f"<td>{event['status']}</td>"
            f"<td>{html.escape(', '.join(markers))}</td>"
            "</tr>"
        )
    cards = "".join(
        f"<div class='card'><strong>{html.escape(name)}</strong><br>Attack probability: {probability:.2f}<br>"
        f"Evidence: {html.escape(', '.join(evidence) or 'none')}</div>"
        for name, probability, evidence in predictions
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Episode {html.escape(episode_id)}</title>
<style>
body{{font:16px system-ui;margin:2rem;max-width:1100px}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccc;padding:.5rem;text-align:left}}th{{background:#f2f4f7}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}}.card{{border:1px solid #bbb;border-radius:8px;padding:1rem}}
code{{font-size:.9em}}
</style></head><body>
<h1>Sanitized episode timeline</h1><p><code>{html.escape(episode_id)}</code></p>
<div class="cards">{cards}</div>
<table><thead><tr><th>#</th><th>Event</th><th>Method</th><th>Path</th><th>Status</th><th>Oracle reveal</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p><em>Oracle markers are shown only in this explanatory view, never to defenders.</em></p>
</body></html>"""
    destination = data_root / "reports" / "timeline" / f"{episode_id}.html"
    atomic_write_text(destination, document, overwrite=True)
    return destination

