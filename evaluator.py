"""
GUARDIAN Evaluator - Bounded Recursion Consensus
Three different model families score independently, then reconcile.

Stage 1: Model A (Claude) scores the finding -> verdict_a
Stage 2: Model B (Grok) evaluates verdict_a -> verdict_b
Stage 3: Model C (Gemini) breaks ties if A and B disagree -> verdict_c

All 3 agree -> HIGH confidence
2/3 agree -> MEDIUM confidence, flag dissenter's reasoning
All disagree -> LOW confidence, return all perspectives

Depth=3 solves infinite regress. Different evaluators, not more evaluators.
"""

import json
from typing import Dict, List, Any
from datetime import datetime
import logging

from . import config

logger = logging.getLogger("guardian.evaluator")


SCORE_PROMPT = """You are an independent threat evaluator. Score this threat assessment.

ASSESSMENT:
{assessment}

CONTEXT:
{context}

{prior_verdict}

Evaluate and respond in JSON:
{{
    "score": <1-10 integer>,
    "verdict": "THREAT" | "BENIGN" | "UNCERTAIN",
    "confidence": <0-100>,
    "reasoning": "your reasoning in 2-3 sentences",
    "key_indicators": ["indicator 1", "indicator 2"]
}}

Be direct. If the prior evaluator got it wrong, say so and explain why."""


def _call_evaluator(model_id: str, prompt: str) -> Dict[str, Any]:
    """Call a single evaluator model."""
    import litellm

    try:
        response = litellm.completion(
            model=model_id,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1024,
            temperature=0.3,  # Lower temp for evaluation consistency
        )
        text = response.choices[0].message.content

        # Parse JSON response
        try:
            # Handle markdown code blocks
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {
                "score": 5, "verdict": "UNCERTAIN", "confidence": 50,
                "reasoning": text[:500], "key_indicators": []
            }

        return {
            "model": model_id,
            "score": int(data.get("score", 5)),
            "verdict": data.get("verdict", "UNCERTAIN"),
            "confidence": int(data.get("confidence", 50)),
            "reasoning": data.get("reasoning", ""),
            "key_indicators": data.get("key_indicators", []),
            "error": None,
        }
    except Exception as e:
        logger.error(f"Evaluator {model_id} error: {e}")
        return {
            "model": model_id, "score": 0, "verdict": "ERROR",
            "confidence": 0, "reasoning": str(e),
            "key_indicators": [], "error": str(e),
        }


def evaluate(assessment: str, context: str = "", models: Dict[str, str] = None) -> Dict[str, Any]:
    """
    Run bounded recursion consensus evaluation.

    Args:
        assessment: The threat assessment text to evaluate
        context: Additional context about the finding
        models: Override model selection (default: config.EVAL_MODELS)

    Returns:
        Dict with confidence_level, agreement_map, verdicts, consensus_score, reasoning_chain
    """
    if models is None:
        models = config.EVAL_MODELS

    model_a = models.get("model_a", config.EVAL_MODELS["model_a"])
    model_b = models.get("model_b", config.EVAL_MODELS["model_b"])
    model_c = models.get("model_c", config.EVAL_MODELS["model_c"])

    start = datetime.now()
    verdicts = []

    # Stage 1: Model A scores independently
    prompt_a = SCORE_PROMPT.format(
        assessment=assessment[:3000],
        context=context[:1000],
        prior_verdict=""
    )
    verdict_a = _call_evaluator(model_a, prompt_a)
    verdict_a["stage"] = 1
    verdicts.append(verdict_a)

    # Stage 2: Model B evaluates with knowledge of verdict_a
    prior_a = f"""PRIOR EVALUATOR ({model_a}) VERDICT:
Score: {verdict_a['score']}/10 | Verdict: {verdict_a['verdict']} | Confidence: {verdict_a['confidence']}%
Reasoning: {verdict_a['reasoning']}

Do you agree or disagree? Provide your own independent assessment."""

    prompt_b = SCORE_PROMPT.format(
        assessment=assessment[:3000],
        context=context[:1000],
        prior_verdict=prior_a
    )
    verdict_b = _call_evaluator(model_b, prompt_b)
    verdict_b["stage"] = 2
    verdicts.append(verdict_b)

    # Stage 3: Model C breaks ties (or confirms consensus)
    prior_ab = f"""TWO PRIOR EVALUATORS:

Evaluator A ({model_a}):
  Score: {verdict_a['score']}/10 | Verdict: {verdict_a['verdict']} | Confidence: {verdict_a['confidence']}%
  Reasoning: {verdict_a['reasoning']}

Evaluator B ({model_b}):
  Score: {verdict_b['score']}/10 | Verdict: {verdict_b['verdict']} | Confidence: {verdict_b['confidence']}%
  Reasoning: {verdict_b['reasoning']}

You are the tiebreaker. If they agree, confirm or challenge. If they disagree, determine who is right and why."""

    prompt_c = SCORE_PROMPT.format(
        assessment=assessment[:3000],
        context=context[:1000],
        prior_verdict=prior_ab
    )
    verdict_c = _call_evaluator(model_c, prompt_c)
    verdict_c["stage"] = 3
    verdicts.append(verdict_c)

    elapsed = (datetime.now() - start).total_seconds()

    # Determine consensus
    valid_verdicts = [v for v in verdicts if not v.get("error")]
    if not valid_verdicts:
        return {
            "confidence_level": "NONE",
            "agreement_map": {},
            "verdicts": verdicts,
            "consensus_score": 0,
            "reasoning_chain": "All evaluators failed.",
            "elapsed": elapsed,
        }

    # Count verdict agreements
    verdict_values = [v["verdict"] for v in valid_verdicts]
    score_values = [v["score"] for v in valid_verdicts]

    # Check agreement
    unique_verdicts = set(verdict_values)
    if len(unique_verdicts) == 1:
        confidence_level = "HIGH"
        consensus_verdict = verdict_values[0]
    elif len(valid_verdicts) >= 2:
        # Find majority
        from collections import Counter
        counts = Counter(verdict_values)
        majority_verdict, majority_count = counts.most_common(1)[0]
        if majority_count >= 2:
            confidence_level = "MEDIUM"
            consensus_verdict = majority_verdict
            # Flag dissenter
            dissenter = next(v for v in valid_verdicts if v["verdict"] != majority_verdict)
            logger.info(f"Dissenter: {dissenter['model']} says {dissenter['verdict']}: {dissenter['reasoning']}")
        else:
            confidence_level = "LOW"
            consensus_verdict = "UNCERTAIN"
    else:
        confidence_level = "LOW"
        consensus_verdict = valid_verdicts[0]["verdict"]

    consensus_score = sum(score_values) / len(score_values) if score_values else 0

    # Build agreement map
    agreement_map = {}
    for v in valid_verdicts:
        agreement_map[v["model"]] = {
            "verdict": v["verdict"],
            "score": v["score"],
            "confidence": v["confidence"],
            "agrees_with_consensus": v["verdict"] == consensus_verdict,
        }

    # Build reasoning chain
    reasoning_parts = []
    for v in valid_verdicts:
        marker = "+" if v["verdict"] == consensus_verdict else "X"
        reasoning_parts.append(f"[{marker}] Stage {v['stage']} ({v['model']}): {v['verdict']} ({v['score']}/10) - {v['reasoning']}")

    return {
        "confidence_level": confidence_level,
        "consensus_verdict": consensus_verdict,
        "consensus_score": round(consensus_score, 1),
        "agreement_map": agreement_map,
        "verdicts": verdicts,
        "reasoning_chain": "\n".join(reasoning_parts),
        "elapsed": elapsed,
    }


def format_evaluation(result: Dict[str, Any]) -> str:
    """Format evaluation result for display."""
    lines = []
    lines.append(f"  Confidence: {result['confidence_level']}")
    lines.append(f"  Verdict: {result.get('consensus_verdict', '?')}")
    lines.append(f"  Score: {result['consensus_score']}/10")
    lines.append(f"  Time: {result['elapsed']:.1f}s")
    lines.append("")

    for model, info in result.get("agreement_map", {}).items():
        marker = "AGREE" if info["agrees_with_consensus"] else "DISSENT"
        lines.append(f"    [{marker}] {model}: {info['verdict']} ({info['score']}/10, {info['confidence']}%)")

    lines.append("")
    lines.append("  Reasoning Chain:")
    for line in result.get("reasoning_chain", "").split("\n"):
        lines.append(f"    {line}")

    return "\n".join(lines)
