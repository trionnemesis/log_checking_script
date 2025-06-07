"""中央設定檔

此模組集中定義所有可調整的參數，例如檔案路徑、模型名稱與各式閾值，
可透過環境變數覆蓋。這樣能讓主程式保持簡潔，並方便日後維護或擴充。"""

import os
from pathlib import Path

# 儲存持久化資料的根目錄。可透過 ``LMS_HOME`` 調整專案位置而不必改程式碼。
# ``data`` 子目錄用來放置 FAISS 向量索引及檔案狀態。
BASE_DIR = Path(os.getenv("LMS_HOME", Path(__file__).resolve().parent)).resolve()
DATA_DIR = BASE_DIR / "data"
LOG_STATE_FILE = DATA_DIR / "file_state.json"
VECTOR_DB_PATH = DATA_DIR / "faiss.index"

# 日誌與輸出結果的路徑，預設位於 ``/var/log``，亦可透過環境變數覆寫。
DEFAULT_TARGET_LOG_DIR = "/var/log/LMS_LOG"
DEFAULT_ANALYSIS_OUTPUT_FILE = "/var/log/analyzer_results.json"
DEFAULT_OPERATIONAL_LOG_FILE = BASE_DIR / "analyzer_script.log"

LMS_TARGET_LOG_DIR = Path(os.getenv("LMS_TARGET_LOG_DIR", DEFAULT_TARGET_LOG_DIR))
LMS_ANALYSIS_OUTPUT_FILE = Path(os.getenv("LMS_ANALYSIS_OUTPUT_FILE", DEFAULT_ANALYSIS_OUTPUT_FILE))
LMS_OPERATIONAL_LOG_FILE = Path(os.getenv("LMS_OPERATIONAL_LOG_FILE", str(DEFAULT_OPERATIONAL_LOG_FILE)))

# 下列參數控制取樣比例、批次大小與成本上限，可依環境需求調整。
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

# Wazuh API 整合設定，若三項皆存在，處理流程會先透過 Wazuh 篩選可疑日誌。
WAZUH_API_URL = os.getenv("WAZUH_API_URL")
WAZUH_API_USER = os.getenv("WAZUH_API_USER")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD")
WAZUH_ENABLED = bool(WAZUH_API_URL and WAZUH_API_USER and WAZUH_API_PASSWORD)

# 確保必要的目錄存在，避免首次執行時因目錄缺失而出錯。
DATA_DIR.mkdir(parents=True, exist_ok=True)
if LMS_ANALYSIS_OUTPUT_FILE.parent != Path("/var/log"):
    LMS_ANALYSIS_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
if LMS_OPERATIONAL_LOG_FILE.parent != Path("/var/log"):
    LMS_OPERATIONAL_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
