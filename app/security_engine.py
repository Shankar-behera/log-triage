"""Deterministic, pattern-based security scanner.

Findings indicate suspicious text patterns, not verified attacks. Counts represent
distinct matching lines per finding type, preventing duplicate patterns on the same
line from inflating a finding's count.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Pattern


@dataclass
class SecurityFinding:
    type: str
    count: int
    severity: str
    description: str
    examples: List[str] = field(default_factory=list)


class SecurityEngine:
    PATTERNS: Dict[str, Dict] = {
        "failed_login": {
            "patterns": [
                r"failed\s*login",
                r"authentication failed",
                r"invalid credentials",
                r"login failed",
                r"\b401\s+unauthorized\b",
            ],
            "severity": "medium",
            "description": "Failed authentication attempts",
        },
        "brute_force": {
            "patterns": [
                r"brute.force",
                r"multiple failed\s*(?:login\s*)?attempts",
                r"too many failures",
                r"rate limit exceeded",
            ],
            "severity": "high",
            "description": "Possible brute-force attack pattern",
        },
        "sql_injection": {
            "patterns": [
                r"\bunion\s+select\b",
                r"\bdrop\s+table\b",
                r"\binsert\s+into\b.{0,200}\bvalues\b",
                r"\bdelete\s+from\b",
                r"'\s*or\s*'1'\s*=\s*'1",
                r"\bsql\s+injection\b",
                r"\bselect\b.{0,500}\bfrom\b.{0,500}\bwhere\b.{0,100}\b1\s*=\s*1\b",
            ],
            "severity": "critical",
            "description": "SQL injection-like pattern detected",
        },
        "xss": {
            "patterns": [
                r"<\s*script\b",
                r"javascript\s*:",
                r"\bonerror\s*=",
                r"\balert\s*\(",
                r"document\.cookie",
                r"cross.site scripting",
            ],
            "severity": "high",
            "description": "Cross-site scripting-like pattern detected",
        },
        "unauthorized_access": {
            "patterns": [
                r"\bunauthorized\b",
                r"\bforbidden\b",
                r"\b403\b",
                r"\bpermission denied\b",
                r"\bnot authorized\b",
            ],
            "severity": "high",
            "description": "Unauthorized access or permission-denial signal",
        },
        "token_issue": {
            "patterns": [
                r"invalid token",
                r"token expired",
                r"jwt error",
                r"session expired",
                r"bearer token",
            ],
            "severity": "medium",
            "description": "Token or session authentication signal",
        },
        "privilege_escalation": {
            "patterns": [
                r"privilege escalation",
                r"sudo attempt",
                r"unauthorized (?:admin|root) access",
            ],
            "severity": "critical",
            "description": "Potential privilege-escalation signal",
        },
        "port_scan": {
            "patterns": [r"\bport scan(?:ning)?\b"],
            "severity": "medium",
            "description": "Port-scanning activity signal",
        },
        "sensitive_data_exposure": {
            "patterns": [
                r"sensitive data exposure",
                r"unauthorized file access",
            ],
            "severity": "high",
            "description": "Sensitive-data or file-exposure signal",
        },
    }

    IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
    IP_CONTEXT_PATTERN = re.compile(
        r"\b(?:fail(?:ed)?|denied|blocked|suspicious|attack|scan(?:ning)?|"
        r"brute.force|unauthorized|malicious|intrusion)\b",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        # Compiled once per instance. Building this at class scope in a
        # comprehension leaks comprehension-local names into class scope
        # in a way some Python versions reject - instance-level is
        # both compatible and equivalent.
        self._compiled_patterns: Dict[str, List[Pattern[str]]] = {
            name: [
                re.compile(pattern, re.IGNORECASE)
                for pattern in config["patterns"]
            ]
            for name, config in self.PATTERNS.items()
        }

        # One compiled expression per finding type reduces Python-level
        # dispatch while retaining the original patterns for compatibility.
        self._combined_patterns: Dict[str, Pattern[str]] = {
            name: re.compile(
                "|".join(f"(?:{pattern})" for pattern in config["patterns"]),
                re.IGNORECASE,
            )
            for name, config in self.PATTERNS.items()
        }

    def analyze(self, log_text: str) -> Dict:
        findings: List[SecurityFinding] = []
        lines = (log_text or "").splitlines()

        for name, config in self.PATTERNS.items():
            matching_lines: List[str] = []

            for line in lines:
                # Count a line once per finding type, even if several patterns
                # match the same line.
                if self._combined_patterns[name].search(line):
                    matching_lines.append(line.strip()[:240])

            if matching_lines:
                findings.append(SecurityFinding(
                    type=name,
                    count=len(matching_lines),
                    severity=config["severity"],
                    description=config["description"],
                    examples=matching_lines[:3],
                ))

        flagged_ips = set()
        for line in lines:
            if not self.IP_CONTEXT_PATTERN.search(line):
                continue

            for match in self.IP_PATTERN.finditer(line):
                candidate = match.group(0)
                try:
                    ipaddress.IPv4Address(candidate)
                except ipaddress.AddressValueError:
                    continue
                flagged_ips.add(candidate)

        if flagged_ips:
            findings.append(SecurityFinding(
                type="flagged_ip_activity",
                count=len(flagged_ips),
                severity="medium",
                description="Valid IPv4 addresses seen alongside suspicious context",
                examples=sorted(flagged_ips)[:5],
            ))

        risk_scores = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        total_risk = sum(
            risk_scores.get(finding.severity, 0) * finding.count
            for finding in findings
        )

        return {
            "findings": [
                {
                    "type": finding.type,
                    "count": finding.count,
                    "severity": finding.severity,
                    "description": finding.description,
                    "examples": finding.examples,
                }
                for finding in findings
            ],
            "flagged_ips": sorted(flagged_ips),
            "total_risk_score": total_risk,
            "risk_level": self._get_risk_level(total_risk),
            "has_security_issues": bool(findings),
        }

    @staticmethod
    def _get_risk_level(score: int) -> str:
        if score >= 20:
            return "critical"
        if score >= 10:
            return "high"
        if score >= 5:
            return "medium"
        if score > 0:
            return "low"
        return "none"


security_engine = SecurityEngine()