"""Stable, content-derived event identifiers and source line metadata."""
import hashlib
import json
from typing import Any

def event_id(event: dict[str, Any], source: str = '', occurrence: int = 1) -> str:
    semantic = {k: event.get(k) for k in ('timestamp', 'severity', 'service', 'message', 'parse_status')}
    payload = json.dumps([source, semantic, occurrence], sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()[:24]

def assign_event_ids(events: list[dict], source: str = '') -> list[dict]:
    seen: dict[str, int] = {}
    for event in events:
        base = json.dumps({k: event.get(k) for k in ('timestamp','severity','service','message','parse_status')}, sort_keys=True, ensure_ascii=False, default=str)
        seen[base] = seen.get(base, 0) + 1
        event['event_id'] = event_id(event, source, seen[base])
        event.setdefault('source', source or '<stdin>')
        event.setdefault('source_line', None)
        event.setdefault('source_end_line', event.get('source_line'))
    return events
