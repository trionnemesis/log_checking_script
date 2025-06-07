"""Central configuration for the log analyzer project.

All tunables such as file paths, model names and thresholds are defined here so
they can easily be modified or injected via environment variables.  This keeps
the rest of the code base clean and focused on business logic.
"""

import os
from pathlib import Path

# Base directories for persistent data.  ``LMS_HOME`` allows moving the project
# without changing code.  ``data`` holds the FAISS index and file state.
BASE_DIR = Path(os.getenv("LMS_HOME", Path(__file__).resolve().parent)).resolve()
DATA_DIR = BASE_DIR / "data"
LOG_STATE_FILE = DATA_DIR / "file_state.json"
VECTOR_DB_PATH = DATA_DIR / "faiss.index"

# Paths for logs and exported results.  They default to ``/var/log`` so in many
# deployments no configuration is necessary, but can be overridden via env vars.
DEFAULT_TARGET_LOG_DIR = "/var/log/LMS_LOG"
DEFAULT_ANALYSIS_OUTPUT_FILE = "/var/log/analyzer_results.json"
DEFAULT_OPERATIONAL_LOG_FILE = BASE_DIR / "analyzer_script.log"

LMS_TARGET_LOG_DIR = Path(os.getenv("LMS_TARGET_LOG_DIR", DEFAULT_TARGET_LOG_DIR))
LMS_ANALYSIS_OUTPUT_FILE = Path(os.getenv("LMS_ANALYSIS_OUTPUT_FILE", DEFAULT_ANALYSIS_OUTPUT_FILE))
LMS_OPERATIONAL_LOG_FILE = Path(os.getenv("LMS_OPERATIONAL_LOG_FILE", str(DEFAULT_OPERATIONAL_LOG_FILE)))

# Processing parameters controlling sampling, batch sizes and cost limits.  They
# can be tuned per environment without modifying code.
CACHE_SIZE = int(os.getenv("LMS_CACHE_SIZE", 10_000))
SAMPLE_TOP_PERCENT = int(os.getenv("LMS_SAMPLE_TOP_PERCENT", 20))
BATCH_SIZE = int(os.getenv("LMS_LLM_BATCH_SIZE", 10))
MAX_HOURLY_COST_USD = float(os.getenv("LMS_MAX_HOURLY_COST_USD", 5.0))
PRICE_IN_PER_1K_TOKENS = float(os.getenv("LMS_PRICE_IN_PER_1K_TOKENS", 0.000125))
PRICE_OUT_PER_1K_TOKENS = float(os.getenv("LMS_PRICE_OUT_PER_1K_TOKENS", 0.000375))
SIM_T_ATTACK_L2_THRESHOLD = float(os.getenv("LMS_SIM_T_ATTACK_L2_THRESHOLD", 0.3))
SIM_N_NORMAL_L2_THRESHOLD = float(os.getenv("LMS_SIM_N_NORMAL_L2_THRESHOLD", 0.2))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
LLM_MODEL_NAME = os.getenv("LMS_LLM_MODEL_NAME", "gemini-1.5-flash-latest")

# External Wazuh API integration settings.  When all three are present the log
# processor will consult Wazuh to pre-filter suspicious lines.
WAZUH_API_URL = os.getenv("WAZUH_API_URL")
WAZUH_API_USER = os.getenv("WAZUH_API_USER")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD")
WAZUH_ENABLED = bool(WAZUH_API_URL and WAZUH_API_USER and WAZUH_API_PASSWORD)

# Ensure directories exist to avoid runtime errors on first launch.
DATA_DIR.mkdir(parents=True, exist_ok=True)
if LMS_ANALYSIS_OUTPUT_FILE.parent != Path("/var/log"):
    LMS_ANALYSIS_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
if LMS_OPERATIONAL_LOG_FILE.parent != Path("/var/log"):
    LMS_OPERATIONAL_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
