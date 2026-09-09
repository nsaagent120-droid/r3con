"""
r3con v7.2 - RAG Engine v2 PRO - ML Embeddings + Hybrid Search
TF-IDF + sentence-transformers + KG + intent
"""
from __future__ import annotations
from typing import Dict, List, Any, Optional
from pathlib import Path
import re
import json
from collections import Counter

try:
    from .embeddings import MLEmbeddingsEngine
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False

class RAGEngineV2:
    """RAG Engine v2 PRO - ML embeddings + hybrid search."""

    INTENT_PATTERNS = {
        "search": [r"show", r"find", r"search", r"list", r"get", r"display"],
        "summarize": [r"summarize", r"summary", r"overview", r"stats", r"statistics"],
        "explain": [r"explain", r"what is", r"describe", r"why", r"how does"],
        "remediation": [r"fix", r"remediate", r"how to fix", r"recommendation", r"solution"],
        "att&ck": [r"mitre", r"att&ck", r"technique", r"tactic", r"attack"],
        "cve": [r"cve", r"vulnerability", r"vuln"],
        "critical": [r"critical", r"high", r"severe", r"urgent"],
        "exploit": [r"exploit", r"poc", r"payload"],
        "compliance": [r"owasp", r"compliance", r"cis", r"nist"],
        "ioc": [r"ioc", r"indicator", r"hash", r"ip", r"domain"],
    }

    def __init__(self, use_embeddings: bool = True):
        self.findings: List[Dict[str, Any]] = []
        self.documents: List[str] = []
        self.embeddings_engine = None

        if use_embeddings and EMBEDDINGS_AVAILABLE:
            try:
                self.embeddings_engine = MLEmbeddingsEngine(use_transformers=True)
            except Exception:
                try:
                    self.embeddings_engine = MLEmbeddingsEngine(use_transformers=False)
                except Exception:
                    self.embeddings_engine = None
        self.use_embeddings = self.embeddings_engine is not None

    def add_findings(self, findings: List[Dict[str, Any]]):
        """Add findings to KG and embeddings."""
        self.findings.extend(findings)

        # Create documents for embeddings
        for finding in findings:
            doc = f"{finding.get('type','')} {finding.get('description','')} {finding.get('file','')} severity {finding.get('severity','')} {finding.get('recommendation','')}"
            self.documents.append(doc)

        # Refit embeddings
        if self.use_embeddings and self.documents:
            try:
                self.embeddings_engine.fit(self.documents)
            except Exception:
                pass

    def _detect_intent(self, question: str) -> str:
        q_lower = question.lower()
        scores = {}

        for intent, patterns in self.INTENT_PATTERNS.items():
            score = 0
            for pat in patterns:
                if re.search(pat, q_lower):
                    score += 1
            if score > 0:
                scores[intent] = score

        if not scores:
            return "search"

        # Return highest scoring intent
        return max(scores.items(), key=lambda x: x[1])[0]

    def query(self, question: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Query RAG engine."""
        intent = self._detect_intent(question)
        context = context or {}

        # Retrieve relevant findings
        relevant = self._retrieve(question, top_k=10)

        # Generate answer based on intent
        answer = self._generate_answer(question, intent, relevant, context)

        return {
            "status": "ok",
            "engine": "rag_v2",
            "intent": intent,
            "question": question,
            "findings": relevant,
            "answer": answer,
            "total_findings": len(self.findings),
            "use_embeddings": self.use_embeddings,
            "embeddings_stats": self.embeddings_engine.get_stats() if self.embeddings_engine else None,
        }

    def _retrieve(self, question: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """Retrieve relevant findings via embeddings or keyword."""
        if not self.findings:
            return []

        if self.use_embeddings and self.embeddings_engine and self.embeddings_engine.fitted:
            try:
                # Use embeddings search
                search_results = self.embeddings_engine.search(question, top_k=top_k, method="hybrid" if self.embeddings_engine.use_transformers else "tfidf")

                relevant = []
                for res in search_results:
                    idx = res.get("index")
                    if idx is not None and 0 <= idx < len(self.findings):
                        finding = self.findings[idx].copy()
                        finding["_score"] = res.get("score", 0)
                        finding["_method"] = res.get("method", "unknown")
                        relevant.append(finding)

                return relevant
            except Exception:
                pass

        # Fallback keyword search
        return self._keyword_search(question, top_k)

    def _keyword_search(self, question: str, top_k: int) -> List[Dict[str, Any]]:
        """Keyword search fallback."""
        q_tokens = set(re.findall(r"[a-zA-Z]{3,}", question.lower()))
        if not q_tokens:
            return self.findings[:top_k]

        scored = []
        for finding in self.findings:
            text = f"{finding.get('type','')} {finding.get('description','')} {finding.get('file','')} {finding.get('severity','')}".lower()
            f_tokens = set(re.findall(r"[a-zA-Z]{3,}", text))

            overlap = len(q_tokens & f_tokens)
            score = overlap / max(1, len(q_tokens))

            # Boost for severity match
            if "critical" in q_tokens and finding.get("severity") == "CRITICAL":
                score += 0.5
            if "high" in q_tokens and finding.get("severity") == "HIGH":
                score += 0.3

            scored.append((score, finding))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [f for score, f in scored[:top_k] if score > 0] or self.findings[:top_k]

    def _generate_answer(self, question: str, intent: str, relevant: List[Dict], context: Dict) -> str:
        """Generate answer based on intent."""

        if not relevant:
            return f"No findings found for query '{question}'. Total findings in KG: {len(self.findings)}"

        if intent == "search":
            critical = [f for f in relevant if f.get("severity") == "CRITICAL"]
            high = [f for f in relevant if f.get("severity") == "HIGH"]

            answer = f"Found {len(relevant)} relevant findings"
            if critical:
                answer += f", including {len(critical)} CRITICAL"
            if high:
                answer += f" and {len(high)} HIGH"
            answer += ":\n\n"

            for i, f in enumerate(relevant[:5], 1):
                answer += f"{i}. [{f.get('severity','')}] {f.get('type','')} in {f.get('file','')}:{f.get('line','')} - {f.get('description','')[:100]}\n"

            return answer

        elif intent == "summarize":
            by_sev = Counter(f.get("severity", "UNKNOWN") for f in self.findings)
            by_type = Counter(f.get("type", "Unknown") for f in self.findings)

            answer = f"Summary of {len(self.findings)} findings:\n"
            answer += f"By severity: {dict(by_sev)}\n"
            answer += f"Top types: {dict(by_type.most_common(5))}\n\n"

            critical = [f for f in self.findings if f.get("severity") == "CRITICAL"]
            if critical:
                answer += f"CRITICAL ({len(critical)}):\n"
                for f in critical[:3]:
                    answer += f"  - {f.get('type')} in {f.get('file','')}\n"

            return answer

        elif intent == "explain":
            if relevant:
                f = relevant[0]
                answer = f"**{f.get('type','')}** ({f.get('severity','')}):\n\n"
                answer += f"{f.get('description','')}\n\n"
                if f.get("cwe"):
                    answer += f"CWE: {f.get('cwe')}\n"
                if f.get("cvss"):
                    answer += f"CVSS: {f.get('cvss')}\n"
                if f.get("mitre"):
                    answer += f"MITRE: {f.get('mitre')}\n"
                answer += f"\nFile: {f.get('file','')}:{f.get('line','')}\n"
                return answer
            return "No finding to explain"

        elif intent == "remediation":
            answer = f"Remediation for {len(relevant)} findings:\n\n"
            for i, f in enumerate(relevant[:5], 1):
                answer += f"{i}. {f.get('type')} in {f.get('file','')}:\n"
                answer += f"   Recommendation: {f.get('recommendation','Review and fix')}\n\n"
            return answer

        elif intent == "att&ck":
            techniques = set()
            for f in relevant:
                mitre = f.get("mitre", [])
                if isinstance(mitre, list):
                    techniques.update(mitre)
                elif isinstance(mitre, str):
                    techniques.add(mitre)

            answer = f"MITRE ATT&CK mapping for {len(relevant)} findings:\n"
            answer += f"Techniques: {', '.join(sorted(list(techniques))[:20])}\n\n"
            for f in relevant[:5]:
                if f.get("mitre"):
                    answer += f"- {f.get('type')}: {f.get('mitre')}\n"
            return answer

        else:
            # Generic
            answer = f"Found {len(relevant)} findings for intent '{intent}':\n\n"
            for f in relevant[:5]:
                answer += f"- [{f.get('severity')}] {f.get('type')} - {f.get('description','')[:80]}\n"
            return answer

    def search_findings(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """Search findings."""
        return self._retrieve(query, top_k)

    def summarize_findings(self) -> Dict[str, Any]:
        """Summarize all findings."""
        if not self.findings:
            return {"status": "ok", "total": 0, "summary": "No findings"}

        by_sev = Counter(f.get("severity", "UNKNOWN") for f in self.findings)
        by_type = Counter(f.get("type", "Unknown") for f in self.findings)
        by_file = Counter(f.get("file", "unknown") for f in self.findings)

        return {
            "status": "ok",
            "total": len(self.findings),
            "by_severity": dict(by_sev),
            "by_type": dict(by_type.most_common(10)),
            "by_file": dict(by_file.most_common(10)),
            "critical": [f for f in self.findings if f.get("severity") == "CRITICAL"][:5],
            "high": [f for f in self.findings if f.get("severity") == "HIGH"][:5],
        }

    def cluster_findings(self, n_clusters: int = 3) -> Dict[str, Any]:
        """Cluster findings via embeddings."""
        if not self.use_embeddings or not self.embeddings_engine:
            return {"status": "error", "error": "embeddings not available"}

        return self.embeddings_engine.cluster(n_clusters=n_clusters)
