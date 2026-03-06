"""
Core advisory engine that evaluates context and provides security guidance.
"""

import json
import os
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class AdvisoryContext:
    """Context information for generating security advice."""
    issue_labels: List[str]
    repo_metadata: Dict[str, Any]
    file_patterns: List[str]
    contributor_intent: Optional[str] = None
    past_patterns: Optional[Dict[str, Any]] = None


@dataclass
class SecurityAdvice:
    """Security advice generated for a contribution."""
    severity: str  # info, warning, high, critical
    title: str
    message: str
    documentation_links: List[str]
    recommendations: List[str]
    timestamp: str


class AdvisoryEngine:
    """Main advisory engine for providing security guidance."""
    
    def __init__(self, config_path: str = "config/security_patterns.json"):
        self.config_path = config_path
        self.security_patterns = self._load_security_patterns()
        self.learning_data = self._load_learning_data()
    
    def _load_security_patterns(self) -> Dict:
        """Load security patterns from configuration."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return self._get_default_patterns()
    
    def _get_default_patterns(self) -> Dict:
        """Return default security patterns."""
        return {
            "file_patterns": {
                "authentication": {
                    "patterns": ["**/auth/**", "**/login/**", "**/password/**"],
                    "severity": "critical",
                    "guidance": "Authentication changes require careful review"
                },
                "api_keys": {
                    "patterns": ["**/*api*key*", "**/*secret*", "**/*token*"],
                    "severity": "critical",
                    "guidance": "Never commit API keys or secrets"
                },
                "database": {
                    "patterns": ["**/*db*", "**/*database*", "**/migrations/**"],
                    "severity": "warning",
                    "guidance": "Database changes should include security considerations"
                },
                "encryption": {
                    "patterns": ["**/*crypto*", "**/*encrypt*", "**/*hash*"],
                    "severity": "critical",
                    "guidance": "Use established cryptographic libraries"
                }
            },
            "label_patterns": {
                "security": {
                    "severity": "critical",
                    "guidance": "Security-related changes require thorough review"
                },
                "authentication": {
                    "severity": "critical",
                    "guidance": "Authentication changes must follow security best practices"
                },
                "data-privacy": {
                    "severity": "critical",
                    "guidance": "Ensure compliance with data privacy regulations"
                },
                "api": {
                    "severity": "warning",
                    "guidance": "API changes should include input validation and rate limiting"
                }
            }
        }
    
    def _load_learning_data(self) -> Dict:
        """Load learning data from past patterns."""
        learning_path = "config/learning_data.json"
        if os.path.exists(learning_path):
            with open(learning_path, 'r') as f:
                return json.load(f)
        return {"patterns": [], "feedback": []}
    
    def evaluate_context(self, context: AdvisoryContext) -> List[SecurityAdvice]:
        """Evaluate context and generate security advice."""
        advice_list = []
        
        # Evaluate based on issue labels
        # FIX 2: Bidirectional matching + hyphen normalisation so that short labels
        # like "auth" or "auth-flow" correctly match the "authentication" pattern key.
        for label in context.issue_labels:
            label_lower = label.lower().replace("-", "_")
            for pattern_key, pattern_data in self.security_patterns.get("label_patterns", {}).items():
                pattern_key_norm = pattern_key.replace("-", "_")
                if pattern_key_norm in label_lower or label_lower in pattern_key_norm:
                    advice = self._generate_advice_from_pattern(
                        pattern_key, pattern_data, "label", context
                    )
                    advice_list.append(advice)
        
        # Evaluate based on file patterns
        for file_path in context.file_patterns:
            for pattern_key, pattern_data in self.security_patterns.get("file_patterns", {}).items():
                if self._matches_pattern(file_path, pattern_data.get("patterns", [])):
                    advice = self._generate_advice_from_pattern(
                        pattern_key, pattern_data, "file", context
                    )
                    advice_list.append(advice)
        
        # Add general security advice
        if not advice_list:
            advice_list.append(self._get_general_advice(context))
        
        # Refine based on learning data
        advice_list = self._refine_with_learning(advice_list, context)
        
        return advice_list
    
    def _matches_pattern(self, file_path: str, patterns: List[str]) -> bool:
        """Check if file path matches any of the patterns (supports ** globstar).

        FIX 1: The previous implementation used fnmatch.fnmatch() which does NOT
        understand '**' (globstar/recursive) syntax. All patterns like '**/auth/**'
        would silently never match. This version translates globstar patterns to
        equivalent regular expressions before matching.
        """
        import fnmatch

        # Normalize path separators to forward slashes
        normalized = file_path.replace("\\", "/")

        for pattern in patterns:
            if "**" in pattern:
                # Translate globstar pattern to a regex:
                #   **/foo  → optional leading directories
                #   foo/**  → optional trailing directories
                #   **      → any path segment(s)
                #   *       → any characters except '/'
                regex = re.escape(pattern)
                regex = regex.replace(r"\*\*/", "(.+/)?")   # leading **/
                regex = regex.replace(r"/\*\*", "(/.*)?")   # trailing /**
                regex = regex.replace(r"\*\*", ".*")         # bare **
                regex = regex.replace(r"\*", "[^/]*")        # single-level *
                if re.fullmatch(regex, normalized):
                    return True
            else:
                if fnmatch.fnmatch(normalized, pattern):
                    return True
        return False
    
    def _generate_advice_from_pattern(
        self, pattern_key: str, pattern_data: Dict, source_type: str, context: AdvisoryContext
    ) -> SecurityAdvice:
        """Generate security advice from a matched pattern."""
        severity = pattern_data.get("severity", "info")
        guidance = pattern_data.get("guidance", "Please review security implications")
        
        # Build recommendations
        recommendations = self._get_recommendations(pattern_key, severity)
        
        # FIX 3: Prefer the 'references' array from the JSON pattern over the
        # hardcoded fallback links, so the enriched OWASP links added to
        # security_patterns.json are actually surfaced in the report.
        doc_links = (
            pattern_data.get("references")
            or self._get_documentation_links(pattern_key)
        )
        
        return SecurityAdvice(
            severity=severity,
            title=f"Security Advisory: {pattern_key.replace('_', ' ').title()}",
            message=guidance,
            documentation_links=doc_links,
            recommendations=recommendations,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def _get_general_advice(self, context: AdvisoryContext) -> SecurityAdvice:
        """Generate general security advice."""
        return SecurityAdvice(
            severity="info",
            title="General Security Guidance",
            message="Thank you for contributing! Please review these general security best practices.",
            documentation_links=[
                "https://owasp.org/www-project-top-ten/",
                "https://cheatsheetseries.owasp.org/"
            ],
            recommendations=[
                "Review OWASP Top 10 security risks",
                "Ensure input validation is in place",
                "Check for proper error handling",
                "Verify authentication and authorization",
                "Avoid hardcoding sensitive information"
            ],
            timestamp=datetime.utcnow().isoformat()
        )
    
    def _get_recommendations(self, pattern_key: str, severity: str) -> List[str]:
        """Get specific recommendations for a pattern."""
        recommendations = {
            "authentication": [
                "Use multi-factor authentication where possible",
                "Implement proper session management",
                "Hash passwords with bcrypt or Argon2",
                "Add rate limiting to prevent brute force attacks"
            ],
            "api_keys": [
                "Use environment variables for secrets",
                "Never commit secrets to version control",
                "Rotate keys regularly",
                "Use a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager)"
            ],
            "database": [
                "Use parameterized queries to prevent SQL injection",
                "Implement proper access controls",
                "Encrypt sensitive data at rest",
                "Validate and sanitize all inputs"
            ],
            "encryption": [
                "Use well-tested cryptographic libraries",
                "Avoid creating custom encryption algorithms",
                "Use strong key lengths (AES-256, RSA-2048+)",
                "Implement proper key management"
            ],
            "security": [
                "Follow the principle of least privilege",
                "Implement defense in depth",
                "Keep security dependencies up to date",
                "Conduct security testing"
            ]
        }
        
        return recommendations.get(pattern_key, [
            "Review security implications carefully",
            "Consult security documentation",
            "Consider security testing"
        ])
    
    def _get_documentation_links(self, pattern_key: str) -> List[str]:
        """Get documentation links for a pattern (fallback when JSON references absent)."""
        docs = {
            "authentication": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
            ],
            "api_keys": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
            ],
            "database": [
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"
            ],
            "encryption": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html"
            ],
            "security": [
                "https://owasp.org/www-project-top-ten/",
                "https://cheatsheetseries.owasp.org/"
            ]
        }
        
        return docs.get(pattern_key, [
            "https://owasp.org/www-project-top-ten/",
            "https://cheatsheetseries.owasp.org/"
        ])
    
    def _refine_with_learning(
        self, advice_list: List[SecurityAdvice], context: AdvisoryContext
    ) -> List[SecurityAdvice]:
        """Refine advice based on learning data."""
        # Check if we have feedback patterns
        feedback = self.learning_data.get("feedback", [])
        
        if feedback:
            # Adjust severity or recommendations based on past feedback
            for advice in advice_list:
                relevant_feedback = [
                    f for f in feedback 
                    if f.get("pattern") == advice.title
                ]
                
                if relevant_feedback:
                    # Calculate average helpfulness
                    avg_helpful = sum(
                        f.get("helpful", 0) for f in relevant_feedback
                    ) / len(relevant_feedback)
                    
                    # If advice was not helpful, adjust it
                    if avg_helpful < 0.5:
                        advice.message += "\n\nNote: This guidance is being refined based on contributor feedback."
        
        return advice_list
    
    def capture_intent(self, intent: str, context: AdvisoryContext) -> None:
        """Capture contributor intent for better guidance."""
        intent_data = {
            "intent": intent,
            "timestamp": datetime.utcnow().isoformat(),
            "context": {
                "labels": context.issue_labels,
                "files": context.file_patterns
            }
        }
        
        # Store intent for learning
        self.learning_data.setdefault("intents", []).append(intent_data)
        self._save_learning_data()
    
    def record_feedback(self, advice_title: str, helpful: bool, comments: str = "") -> None:
        """Record feedback on advice for learning loop."""
        feedback_data = {
            "pattern": advice_title,
            "helpful": 1 if helpful else 0,
            "comments": comments,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.learning_data.setdefault("feedback", []).append(feedback_data)
        self._save_learning_data()
    
    def _save_learning_data(self) -> None:
        """Save learning data to file."""
        learning_path = "config/learning_data.json"
        os.makedirs(os.path.dirname(learning_path), exist_ok=True)
        with open(learning_path, 'w') as f:
            json.dump(self.learning_data, f, indent=2)
    
    def generate_report(self, advice_list: List[SecurityAdvice]) -> str:
        """Generate a formatted report from advice list."""
        if not advice_list:
            return "No specific security advisories for this contribution."
        
        report = ["# 🛡️ BLT Preflight Security Advisory\n"]
        report.append("This advisory system helps you understand security expectations before contributing.\n")
        report.append("---\n")
        
        # FIX 4: Group by all four supported severity levels (info, warning, high, critical).
        # Previously "high" was not handled, causing those advisories to be silently dropped
        # from the report even though the JSON patterns were correctly classified.
        critical = [a for a in advice_list if a.severity == "critical"]
        high     = [a for a in advice_list if a.severity == "high"]
        warnings = [a for a in advice_list if a.severity == "warning"]
        info     = [a for a in advice_list if a.severity == "info"]
        
        if critical:
            report.append("## 🔴 Critical Security Considerations\n")
            for advice in critical:
                report.append(self._format_advice(advice))
        
        if high:
            report.append("## 🟠 High Severity Security Considerations\n")
            for advice in high:
                report.append(self._format_advice(advice))
        
        if warnings:
            report.append("## 🟡 Security Warnings\n")
            for advice in warnings:
                report.append(self._format_advice(advice))
        
        if info:
            report.append("## 🔵 Security Information\n")
            for advice in info:
                report.append(self._format_advice(advice))
        
        report.append("\n---")
        report.append("\n*This is an advisory system - not enforcement. These suggestions help prevent common security issues.*")
        report.append("\n*Questions? Check our [documentation](docs/SECURITY_GUIDANCE.md) or ask a maintainer.*")
        
        return "\n".join(report)
    
    def _format_advice(self, advice: SecurityAdvice) -> str:
        """Format individual advice for display."""
        lines = [f"### {advice.title}\n"]
        lines.append(f"{advice.message}\n")
        
        if advice.recommendations:
            lines.append("**Recommendations:**")
            for rec in advice.recommendations:
                lines.append(f"- {rec}")
            lines.append("")
        
        if advice.documentation_links:
            lines.append("**Learn more:**")
            for link in advice.documentation_links:
                lines.append(f"- {link}")
            lines.append("")
        
        return "\n".join(lines)
