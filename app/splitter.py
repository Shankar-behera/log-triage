"""Log splitter. Stdlib only."""
from typing import List
import re

from app.config import settings


class LogSplitter:
    def split_simple(self, log_text: str, lines_per_chunk: int = None) -> List[str]:
        lines_per_chunk = lines_per_chunk or settings.LINES_PER_CHUNK
        lines = log_text.splitlines()
        chunks = []
        for i in range(0, len(lines), lines_per_chunk):
            chunk = "\n".join(lines[i : i + lines_per_chunk])
            if chunk.strip():
                chunks.append(chunk)
        return chunks

    def split_by_error_boundaries(self, log_text: str) -> List[str]:
        boundary = re.compile(
            r"\n(?=\[?\d{4}-\d{2}-\d{2}.{0,20}?(?:ERROR|FATAL|CRITICAL|SECURITY|Exception|Traceback))",
            re.IGNORECASE,
        )
        pieces = boundary.split(log_text)
        return [p.strip() for p in pieces if p.strip()]

    def split_smart(self, log_text: str) -> List[str]:
        total_lines = len(log_text.splitlines())
        if total_lines < 100:
            return [log_text]
        elif total_lines < 1000:
            return self.split_simple(log_text)
        else:
            return self.split_by_error_boundaries(log_text)

    def split_logs(self, log_text: str, strategy: str = "smart") -> List[str]:
        if not log_text or not log_text.strip():
            return []
        strategy = strategy.lower()
        if strategy == "simple":
            return self.split_simple(log_text)
        elif strategy == "error":
            return self.split_by_error_boundaries(log_text)
        return self.split_smart(log_text)


log_splitter = LogSplitter()