"""
GUARDIAN Configuration
"""

import os

def env(key: str, default: str = "") -> str:
    return os.getenv(key, default)

# Cross-family model configuration (litellm format)
RELAY_MODELS = {
    "primary": env("GUARDIAN_PRIMARY", "anthropic/claude-sonnet-4-20250514"),
    "secondary": env("GUARDIAN_SECONDARY", "xai/grok-3-mini-beta"),
    "tertiary": env("GUARDIAN_TERTIARY", "google/gemini-2.0-flash"),
}

# Evaluator models (bounded recursion uses all three families)
EVAL_MODELS = {
    "model_a": RELAY_MODELS["primary"],
    "model_b": RELAY_MODELS["secondary"],
    "model_c": RELAY_MODELS["tertiary"],
}

# Storage
VAULT_DB = env("GUARDIAN_VAULT", "./guardian_vault.db")
GRAPH_DB = env("GUARDIAN_GRAPH", "./guardian_graph.db")

# Thresholds
CONFIDENCE_THRESHOLD = int(env("GUARDIAN_THRESHOLD", "7"))
MAX_RELAY_TOKENS = int(env("GUARDIAN_MAX_TOKENS", "4096"))
RELAY_TEMPERATURE = float(env("GUARDIAN_TEMPERATURE", "0.7"))

# Sensor defaults
PYPI_CHECK_HOURS = int(env("GUARDIAN_PYPI_HOURS", "24"))
WATCH_INTERVAL_MIN = int(env("GUARDIAN_WATCH_INTERVAL", "15"))
