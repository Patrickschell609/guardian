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
