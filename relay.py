"""
GUARDIAN Relay - Cross-Family Analysis Chain
Problem -> Model A -> Model B -> Model A -> Model B -> Model C -> Done

Each model has ONE job. Full context passes forward. No drift.
Adapted from Swarm relay.py.
"""

import json
from datetime import datetime

from . import config
from .vault import get_best_prior, save_solution, get_vault_stats

VAULT_ENABLED = True


# Relay stages using config models
STAGES = [
    {
        "name": "IDEATION",
        "model": "primary",
        "prompt": """You are the IDEATION specialist. Analyze this threat finding and create a comprehensive assessment plan.

FINDING:
{problem}

{prior_knowledge}

Your task:
1. Analyze the threat deeply
2. Break it down into components (indicators, TTPs, affected systems)
3. Create a detailed analysis plan
4. Include relevant threat frameworks (MITRE ATT&CK, kill chain)
5. Be thorough - your output goes to the analysis team
{prior_instruction}

Output a complete threat assessment plan."""
    },
    {
        "name": "ANALYSIS",
        "model": "secondary",
        "prompt": """You are the ANALYSIS specialist. You received an assessment plan from the ideation team.

ORIGINAL FINDING:
{problem}

ASSESSMENT PLAN:
{previous_output}

Your task:
1. Execute the analysis plan
2. Identify specific indicators of compromise
3. Map to MITRE ATT&CK techniques where applicable
4. Assess severity and confidence level
5. Your output goes to review - make it solid

Output the complete analysis with specific findings."""
    },
    {
        "name": "REVIEW",
        "model": "primary",
        "prompt": """You are the REVIEW specialist. Review this threat analysis.

ORIGINAL FINDING:
{problem}

ANALYSIS:
{previous_output}

Your task:
1. Review the analysis for correctness and completeness
2. Identify any gaps, false positives, or missed indicators
3. Add context from known threat actor behaviors
4. Challenge assumptions
5. Your additions go back for refinement

Output your review with specific additions and corrections."""
    },
    {
        "name": "REFINEMENT",
        "model": "secondary",
        "prompt": """You are the REFINEMENT specialist. Polish the reviewed analysis.

ORIGINAL FINDING:
{problem}

REVIEWED ANALYSIS:
{previous_output}

Your task:
1. Apply all suggested improvements
2. Produce a clear, actionable threat assessment
3. Include confidence levels for each finding
4. Prioritize remediation actions
5. Make it deployment-ready

Output the refined threat assessment."""
    },
    {
        "name": "REASONING",
        "model": "primary",
        "prompt": """You are the REASONING specialist. Final verification.

ORIGINAL FINDING:
{problem}

REFINED ASSESSMENT:
{previous_output}

Your task:
1. Deep reasoning check - does this assessment accurately characterize the threat?
2. Verify logic and evidence chain
3. Final confidence calibration
4. Ensure actionable recommendations are clear
5. This is the final output

Output the final, verified threat assessment."""
    },
]


def call_model(model_key: str, prompt: str) -> str:
    """Call a model using litellm with config-based model selection."""
    import litellm

    model = config.RELAY_MODELS.get(model_key, config.RELAY_MODELS["primary"])

    try:
        response = litellm.completion(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=config.MAX_RELAY_TOKENS,
            temperature=config.RELAY_TEMPERATURE,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"ERROR from {model_key} ({model}): {str(e)}"


def run_relay(problem: str, verbose: bool = True, use_vault: bool = True, stages_override: list = None) -> dict:
    """
    Run the relay chain. Returns dict with output, model_chain, elapsed, score.

    Args:
        stages_override: If provided, only run stages whose name is in this list.
                         e.g. ["IDEATION", "ANALYSIS", "REASONING"] for --fast mode.
    """
    total_start = datetime.now()

    if verbose:
        print(f"\n{'='*60}")
        print(f"  GUARDIAN RELAY - Cross-Family Analysis")
        print(f"{'='*60}")
        print(f"  Finding: {problem[:100]}...")

    # Check vault for prior solution
    prior_knowledge = ""
    prior_instruction = ""
    prior = None

    if use_vault and VAULT_ENABLED:
        prior = get_best_prior(problem)
        if prior:
            if verbose:
                print(f"  Vault: Found {prior['match_type']} match (score: {prior['score']}/10)")
            prior_knowledge = f"""PRIOR ANALYSIS (Score: {prior['score']}/10):
{prior['solution'][:2000]}
---"""
            prior_instruction = "\n6. BUILD ON the prior analysis above - refine it, don't start from scratch"
        elif verbose:
            print(f"  Vault: No prior - starting fresh")

    previous_output = ""
    model_chain = []

    active_stages = STAGES
    if stages_override:
        active_stages = [s for s in STAGES if s["name"] in stages_override]

    total = len(active_stages)
    for i, stage in enumerate(active_stages):
        stage_name = stage["name"]
        model_key = stage["model"]
        model_chain.append(model_key)

        if verbose:
            model_id = config.RELAY_MODELS.get(model_key, "?")
            print(f"\n  Stage {i+1}/{total}: {stage_name} ({model_id})")

        prompt = stage["prompt"].format(
            problem=problem,
            previous_output=previous_output,
            prior_knowledge=prior_knowledge if i == 0 else "",
            prior_instruction=prior_instruction if i == 0 else ""
        )

        start = datetime.now()
        output = call_model(model_key, prompt)
        elapsed = (datetime.now() - start).total_seconds()

        if verbose:
            print(f"    Done in {elapsed:.1f}s ({len(output)} chars)")

        previous_output = output

        if output.startswith("ERROR"):
            if verbose:
                print(f"\n  RELAY FAILED at {stage_name}: {output[:100]}")
            return {"output": output, "model_chain": model_chain,
                    "elapsed": (datetime.now() - total_start).total_seconds(),
                    "score": 0, "error": True}

    total_elapsed = (datetime.now() - total_start).total_seconds()

    if verbose:
        print(f"\n{'='*60}")
        print(f"  RELAY COMPLETE ({total_elapsed:.1f}s)")
        print(f"{'='*60}")

    # Save to vault
    score = 8
    if use_vault and VAULT_ENABLED:
        if prior and prior['score'] >= 8:
            score = min(10, prior['score'] + 1)
        solution_id = save_solution(
            problem=problem, solution=previous_output,
            score=score, model_chain="->".join(model_chain),
            elapsed=total_elapsed
        )
        if verbose:
            print(f"  Saved to vault (#{solution_id}, score {score}/10)")

    return {
        "output": previous_output,
        "model_chain": model_chain,
        "elapsed": total_elapsed,
        "score": score,
        "error": False,
    }
