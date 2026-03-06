"""
Multi-Model LLM Analyst
Uses litellm to route to Claude, Grok, and Gemini for consensus analysis.
Adapted from Jarvis llm_analyst.py.
"""

import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logger = logging.getLogger("guardian.consensus")


@dataclass
class ModelAnalysis:
    model: str
    analysis: str
    confidence: float
    key_points: List[str]
    recommended_actions: List[str]
    timestamp: datetime
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "model": self.model, "analysis": self.analysis,
            "confidence": self.confidence, "key_points": self.key_points,
            "recommended_actions": self.recommended_actions,
            "timestamp": self.timestamp.isoformat(), "error": self.error,
        }


@dataclass
class ConsensusAnalysis:
    suggestion_id: str
    models: List[ModelAnalysis]
    consensus: str
    disagreements: List[str]
    confidence: float
    timestamp: datetime

    def to_dict(self) -> Dict:
        return {
            "suggestion_id": self.suggestion_id,
            "models": [m.to_dict() for m in self.models],
            "consensus": self.consensus, "disagreements": self.disagreements,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


ANALYST_SYSTEM = """You are a threat intelligence analyst. Analyze the following finding and provide:

1. ASSESSMENT: Is this a genuine threat signal or noise? Why?
2. CONTEXT: What broader patterns does this fit into?
3. IMPLICATIONS: What could this mean if true?
4. CONFIDENCE: How confident are you (0-100)?
5. ACTIONS: What should an analyst do next?

Respond in JSON format:
{
    "assessment": "your analysis",
    "context": "broader context",
    "implications": "what this means",
    "confidence": 75,
    "key_points": ["point 1", "point 2"],
    "recommended_actions": ["action 1", "action 2"]
}"""


def _call_model(model_id: str, prompt: str, model_name: str = "") -> ModelAnalysis:
    """Call a model via litellm."""
    try:
        import litellm
        response = litellm.completion(
            model=model_id,
            messages=[
                {"role": "system", "content": ANALYST_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1024,
            temperature=0.7,
        )
        text = response.choices[0].message.content

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {"assessment": text, "confidence": 50, "key_points": [], "recommended_actions": []}

        return ModelAnalysis(
            model=model_name or model_id,
            analysis=data.get("assessment", "") + "\n" + data.get("context", "") + "\n" + data.get("implications", ""),
            confidence=data.get("confidence", 50) / 100,
            key_points=data.get("key_points", []),
            recommended_actions=data.get("recommended_actions", []),
            timestamp=datetime.utcnow(),
        )
    except Exception as e:
        logger.error(f"Model {model_id} error: {e}")
        return ModelAnalysis(
            model=model_name or model_id, analysis="", confidence=0,
            key_points=[], recommended_actions=[],
            timestamp=datetime.utcnow(), error=str(e),
        )


def analyze_finding(finding: Dict, models: Dict[str, str] = None, parallel: bool = True) -> ConsensusAnalysis:
    """
    Analyze a finding with multiple model families.

    Args:
        finding: Dict with 'title', 'description', 'severity', 'evidence' keys
        models: Dict mapping name -> litellm model ID
        parallel: Run models in parallel
    """
    from .. import config
    if models is None:
        models = config.RELAY_MODELS

    prompt = f"""THREAT FINDING TO ANALYZE:

Title: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
Category: {finding.get('category', 'Unknown')}

Description:
{finding.get('description', 'No description')}

Evidence:
{json.dumps(finding.get('evidence', []), indent=2, default=str)}

Analyze this threat finding."""

    model_results = []

    if parallel:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(_call_model, model_id, prompt, name): name
                for name, model_id in models.items()
            }
            for future in as_completed(futures):
                try:
                    model_results.append(future.result())
                except Exception as e:
                    logger.error(f"Model {futures[future]} failed: {e}")
    else:
        for name, model_id in models.items():
            model_results.append(_call_model(model_id, prompt, name))

    # Build consensus
    valid = [m for m in model_results if not m.error]
    if not valid:
        return ConsensusAnalysis(
            suggestion_id=finding.get('id', 'unknown'), models=model_results,
            consensus="All models failed.", disagreements=[], confidence=0,
            timestamp=datetime.utcnow(),
        )

    confidence = sum(m.confidence for m in valid) / len(valid)
    confidences = [m.confidence for m in valid]
    disagreements = []
    if max(confidences) - min(confidences) > 0.3:
        high = max(valid, key=lambda m: m.confidence)
        low = min(valid, key=lambda m: m.confidence)
        disagreements.append(
            f"{high.model} confident ({high.confidence:.0%}) vs {low.model} uncertain ({low.confidence:.0%})"
        )

    consensus = f"Analyzed by {len(valid)} models. "
    if confidence > 0.7:
        consensus += "HIGH CONFIDENCE signal. "
    elif confidence > 0.4:
        consensus += "MODERATE confidence. "
    else:
        consensus += "LOW confidence - may be noise. "
    if disagreements:
        consensus += "Models disagree - warrants investigation."
    else:
        consensus += "Models largely agree."

    return ConsensusAnalysis(
        suggestion_id=finding.get('id', 'unknown'), models=model_results,
        consensus=consensus, disagreements=disagreements,
        confidence=confidence, timestamp=datetime.utcnow(),
    )
