"""
r3con v7.0 - AI RAG Engine PRO
RAG over knowledge graph + findings + embeddings
"""
from __future__ import annotations
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import re
from collections import Counter

class RAGEngine:
    """RAG Engine PRO - retrieval augmented generation over knowledge base."""

    def __init__(self):
        self.knowledge_graph = None
        try:
            from modules.knowledge.graph import KnowledgeGraph
            self.knowledge_graph = KnowledgeGraph()
        except Exception:
            pass

    def query(self, question: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Answer natural language query over findings and knowledge."""
        question_lower = question.lower()

        result: Dict[str, Any] = {
            "status": "ok",
            "engine": "rag_engine",
            "question": question,
        }

        # Parse intent
        intent = self._detect_intent(question_lower)
        result["intent"] = intent

        # Retrieve relevant context
        retrieved = self._retrieve_context(question, context)
        result["retrieved"] = retrieved

        # Generate answer
        answer = self._generate_answer(question, intent, retrieved, context)
        result["answer"] = answer
        result["sources"] = retrieved.get("sources", [])[:10]

        return result

    def _detect_intent(self, question: str) -> str:
        """Detect query intent."""
        if any(kw in question for kw in ["how many", "count", "total", "number"]):
            return "count"
        if any(kw in question for kw in ["what is", "explain", "describe", "what does"]):
            return "explain"
        if any(kw in question for kw in ["show", "list", "find", "search", "get"]):
            return "search"
        if any(kw in question for kw in ["is there", "are there", "any", "exists"]):
            return "existence"
        if any(kw in question for kw in ["critical", "high", "severity", "risk"]):
            return "severity_filter"
        if any(kw in question for kw in ["malware", "family", "trojan", "ransomware"]):
            return "malware_query"
        if any(kw in question for kw in ["c2", "beacon", "network", "pcap", "ip", "domain"]):
            return "network_query"
        if any(kw in question for kw in ["fix", "patch", "mitigate", "recommend"]):
            return "remediation"
        if any(kw in question for kw in ["compare", "diff", "difference"]):
            return "comparison"
        return "general"

    def _retrieve_context(self, question: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Retrieve relevant context from knowledge graph and findings."""
        retrieved: Dict[str, Any] = {"findings": [], "knowledge": [], "sources": []}

        # From provided context
        if context:
            findings = context.get("findings", [])
            if findings:
                # Simple keyword matching
                question_words = set(re.findall(r"\w+", question.lower()))
                scored = []
                for finding in findings[:200]:
                    f_text = f"{finding.get('type','')} {finding.get('description','')}".lower()
                    f_words = set(re.findall(r"\w+", f_text))
                    overlap = len(question_words & f_words)
                    if overlap > 0:
                        scored.append((overlap, finding))

                scored.sort(key=lambda x: x[0], reverse=True)
                retrieved["findings"] = [f for _, f in scored[:20]]
                retrieved["sources"].extend([f"finding:{f.get('type','')}" for _, f in scored[:10]])

        # From knowledge graph
        if self.knowledge_graph:
            try:
                kg_results = self.knowledge_graph.search(question, limit=10)
                retrieved["knowledge"] = kg_results
                retrieved["sources"].extend([f"kg:{r.get('id','')}" for r in kg_results[:5]])
            except Exception:
                pass

        return retrieved

    def _generate_answer(self, question: str, intent: str, retrieved: Dict[str, Any], context: Dict[str, Any] = None) -> str:
        """Generate answer based on intent and retrieved context."""

        findings = retrieved.get("findings", [])
        knowledge = retrieved.get("knowledge", [])

        if intent == "count":
            if context and "findings" in context:
                total = len(context["findings"])
                critical = len([f for f in context["findings"] if f.get("severity") == "CRITICAL"])
                high = len([f for f in context["findings"] if f.get("severity") == "HIGH"])
                return f"Total findings: {total}. Critical: {critical}, High: {high}. Retrieved {len(findings)} relevant to your query."

        elif intent == "existence":
            if findings:
                return f"Yes, found {len(findings)} relevant findings: {', '.join(f.get('type','unknown') for f in findings[:5])}"
            else:
                return "No relevant findings found for your query."

        elif intent == "search":
            if findings:
                result = f"Found {len(findings)} findings:\n"
                for f in findings[:10]:
                    result += f"- [{f.get('severity','INFO')}] {f.get('type','')}: {f.get('description','')[:80]}\n"
                return result
            else:
                return "No findings match your search."

        elif intent == "severity_filter":
            # Extract severity from question
            sev = "CRITICAL" if "critical" in question.lower() else "HIGH" if "high" in question.lower() else "MEDIUM"
            if context and "findings" in context:
                filtered = [f for f in context["findings"] if f.get("severity") == sev]
                return f"Found {len(filtered)} {sev} findings. Examples: {', '.join(f.get('type','') for f in filtered[:5])}"

        elif intent == "malware_query":
            if context and "malware" in context:
                malware = context["malware"]
                summary = malware.get("summary", {})
                return f"Malware verdict: {summary.get('verdict','UNKNOWN')}, Score: {summary.get('score',0)}, Family: {summary.get('primary_family','None')}, IoCs: {summary.get('ioc_count',0)}"
            else:
                return "No malware analysis in context. Run malware analysis first."

        elif intent == "network_query":
            if context and "network" in context:
                net = context["network"]
                summary = net.get("summary", {})
                return f"Network: {summary.get('total_flows',0)} flows, {summary.get('total_findings',0)} findings, {summary.get('threat_count',0)} threats, {summary.get('beacon_count',0)} beacons"
            else:
                return "No network analysis in context. Run network analysis first."

        elif intent == "remediation":
            if findings:
                remediations = list(set(f.get("recommendation", "") for f in findings if f.get("recommendation")))
                if remediations:
                    return f"Remediation recommendations:\n" + "\n".join(f"- {r[:100]}" for r in remediations[:10])
                else:
                    return f"Found {len(findings)} findings but no specific remediation. General: review code, validate inputs, use safe functions."
            else:
                return "No findings to remediate."

        elif intent == "explain":
            # Try to explain finding type
            if findings:
                f = findings[0]
                return f"{f.get('type','')}: {f.get('description','')} - Severity {f.get('severity','')}. Recommendation: {f.get('recommendation','Review code')}"
            else:
                return "I need more context to explain. Provide findings or be more specific."

        # General
        if findings:
            return f"Based on {len(findings)} relevant findings and {len(knowledge)} knowledge entries, here's what I found: {findings[0].get('description','')[:200]}"
        else:
            return "I couldn't find relevant information. Try rephrasing or provide more context with findings."

    def search_findings(self, query: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Semantic search over findings (keyword-based)."""
        query_words = set(re.findall(r"\w+", query.lower()))
        scored = []

        for finding in findings:
            f_text = f"{finding.get('type','')} {finding.get('description','')} {finding.get('severity','')}".lower()
            f_words = set(re.findall(r"\w+", f_text))
            overlap = len(query_words & f_words)

            # Bonus for exact type match
            if query.lower() in f_text:
                overlap += 5

            if overlap > 0:
                scored.append((overlap, finding))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [f for _, f in scored[:20]]

    def summarize_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Summarize findings."""
        if not findings:
            return "No findings to summarize."

        total = len(findings)
        by_sev = Counter(f.get("severity", "INFO") for f in findings)
        by_type = Counter(f.get("type", "unknown") for f in findings)

        summary = f"Summary of {total} findings:\n"
        summary += f"By severity: {dict(by_sev)}\n"
        summary += f"Top types: {', '.join(f'{t}({c})' for t, c in by_type.most_common(5))}\n"

        critical = [f for f in findings if f.get("severity") == "CRITICAL"][:3]
        if critical:
            summary += f"\nCritical findings:\n"
            for f in critical:
                summary += f"- {f.get('type','')}: {f.get('description','')[:100]}\n"

        return summary
