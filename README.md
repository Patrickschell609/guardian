# GUARDIAN - Autonomous Cross-Family Threat Hunting

**The Second AI Dilemma:** the first nation to deploy autonomous AI gains a gap that widens, not closes. GUARDIAN is the building block -- an MIT-licensed tool that packages supply chain sensors, intelligence analysis, and cross-family AI consensus into a single pipeline anyone can run. The thesis: **different AI families catch what single models miss.**

Bounded recursion (depth=3) with three model families produces calibrated confidence without infinite regress. Compound learning (vault) means run 100 is smarter than run 1.

## Architecture

```
SENSORS -----> GRAPH -----> PATTERNS -----> RELAY -----> EVALUATOR -----> VAULT
(Lazarus)      (Jarvis)     (Jarvis)        (Swarm)      (NEW)            (Swarm)
```

- **Sensors**: Persistence scanner, PyPI feed monitor, supply chain crossref, ICS/SCADA watchdog
- **Graph**: In-memory knowledge graph with SQLite persistence, entity resolution
- **Patterns**: Temporal clusters, recurring entities, shared networks, attack patterns
- **Relay**: 5-stage cross-family analysis chain (Model A -> B -> A -> B -> A)
- **Evaluator**: 3-model bounded recursion consensus (Claude/Grok/Gemini score independently, then reconcile)
- **Vault**: SQLite FTS archive -- successful analyses compound over time

## Quickstart

```bash
git clone https://github.com/Patrickschell609/guardian.git
cd guardian
cp .env.example .env
# Add at least one API key to .env

pip install -r requirements.txt

# Demo: cross-family consensus on a simulated supply chain attack
python -m guardian.cli demo

# Scan a local package/directory for persistence mechanisms
python -m guardian.cli scan /path/to/package

# Scan a PyPI package (downloads without installing)
python -m guardian.cli scan pypi:some-package

# Continuous monitoring (PyPI feed + ICS/SCADA watchdog)
python -m guardian.cli watch

# Vault statistics
python -m guardian.cli stats
```

## Docker

```bash
cp .env.example .env
# Add API keys
docker compose up
```

## Cross-Family Consensus

The evaluator runs bounded recursion at depth=3:

```
Stage 1: Model A (Claude) scores independently --> verdict_a
Stage 2: Model B (Grok) evaluates verdict_a    --> verdict_b
Stage 3: Model C (Gemini) breaks ties           --> verdict_c
```

- **All 3 agree** -> HIGH confidence
- **2/3 agree** -> MEDIUM confidence, flag dissenter's reasoning
- **All disagree** -> LOW confidence, return all perspectives

You don't need evaluators all the way down. You need *different* evaluators.

## Example: Demo Run

```
$ python -m guardian.cli demo

  ============================================================
  GUARDIAN DEMO - Cross-Family Consensus
  ============================================================

  Running 5-stage cross-family relay...

  ============================================================
  GUARDIAN RELAY - Cross-Family Analysis
  ============================================================
  Finding: SIMULATED THREAT FINDING: Package: modbus-controller-v2 (PyPI) First published: 2 d...
  Vault: No prior - starting fresh

  Stage 1/5: IDEATION (anthropic/claude-sonnet-4-20250514)
    Done in 8.2s (2847 chars)

  Stage 2/5: ANALYSIS (xai/grok-3-mini-beta)
    Done in 5.1s (3102 chars)

  Stage 3/5: REVIEW (anthropic/claude-sonnet-4-20250514)
    Done in 7.8s (2956 chars)

  Stage 4/5: REFINEMENT (xai/grok-3-mini-beta)
    Done in 4.9s (3211 chars)

  Stage 5/5: REASONING (anthropic/claude-sonnet-4-20250514)
    Done in 9.1s (2680 chars)

  ============================================================
  RELAY COMPLETE (35.1s)
  ============================================================
  Saved to vault (#1, score 8/10)

  Running bounded recursion evaluator (depth=3)...

  ============================================================
  EVALUATION RESULTS
  ============================================================
  Confidence: HIGH
  Verdict: THREAT
  Score: 9.3/10
  Time: 12.4s

    [AGREE]   anthropic/claude-sonnet-4-20250514: THREAT (9/10, 95%)
    [AGREE]   xai/grok-3-mini-beta: THREAT (9/10, 92%)
    [AGREE]   google/gemini-2.0-flash: THREAT (10/10, 97%)

  Reasoning Chain:
    [+] Stage 1 (claude): THREAT (9/10) - Multiple CRITICAL persistence mechanisms
        including GC callbacks and import hooks indicate sophisticated supply chain attack.
    [+] Stage 2 (grok): THREAT (9/10) - Agrees with Stage 1. The combination of
        C2 beacon + env exfil + obfuscated payload is textbook APT supply chain.
    [+] Stage 3 (gemini): THREAT (10/10) - Both prior evaluators correctly identified
        this as malicious. The zombie repo name squatting adds attribution context.

  Vault: 1 solutions, avg score 8.0/10

  ============================================================
  DEMO COMPLETE
  Verdict: THREAT (HIGH)
  Score: 9.3/10
  3 model families, 8 stages, 1 consensus
  ============================================================
```

The demo runs a simulated supply chain attack (modbus-controller-v2 with GC callback persistence, import hook injection, C2 beacon, and obfuscated payload) through the full pipeline. All three model families independently identify it as a threat with 92-97% confidence.

## Modes

| Mode | Command | Models | Stages | Use Case |
|------|---------|--------|--------|----------|
| Full | `guardian scan <path>` | 3 families | All 6 | Production analysis |
| Fast | `guardian scan --fast <path>` | 2 families | Relay (3-stage) | Quick triage |
| Cheap | `guardian scan --cheap <path>` | 1 family | Sensors only | Bulk screening |
| Watch | `guardian watch` | 3 families | Full pipeline on alerts | Continuous monitoring |
| Demo | `guardian demo` | 3 families | Full pipeline | Proof of concept |

## Dependencies

```
litellm>=1.40      # Universal LLM routing (Claude, Grok, Gemini, etc.)
requests>=2.31     # HTTP calls for sensors
python-dotenv>=1.0 # .env file loading
```

Everything else is stdlib (sqlite3, json, re, ast, pathlib, xml, urllib).

## What This Proves

- Cross-family consensus catches what single models miss
- Bounded recursion (depth=3) is tractable and sufficient
- Compound learning (vault) means run 100 is smarter than run 1
- The building block is real -- swap sensors, point at any threat surface

## License

MIT
