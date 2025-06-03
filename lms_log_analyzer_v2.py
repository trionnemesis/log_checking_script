from __future__ import annotations

# ────────────────────────────
# Python 標準函式庫
# ────────────────────────────
import bz2
import gzip
import hashlib
import io
import json
import os
import random
import sys
import time
import logging
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

# ────────────────────────────
# 第三方函式庫（請先安裝）
# ────────────────────────────
#   pip install faiss-cpu google-generativeai langchain-core langchain-google-genai sentence-transformers
try:
    import faiss
except ImportError:
    print("[WARN] 未安裝 faiss-cpu，向量搜尋功能停用。請執行: pip install faiss-cpu")
    faiss = None
try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_core.prompts import PromptTemplate
    from langchain_core.runnables import Runnable
    from langchain_core.outputs import LLMResult
except ImportError:
    print("[WARN] 未安裝 LangChain / Google GenAI，LLM 分析功能停用。請執行: pip install langchain-google-genai langchain-core")
    ChatGoogleGenerativeAI = None
    PromptTemplate = None
    Runnable = None
    LLMResult = None
try:
    from sentence_transformers import SentenceTransformer
    EMBEDDING_MODEL_NAME_DEFAULT = 'paraphrase-multilingual-MiniLM-L12-v2'
    EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", EMBEDDING_MODEL_NAME_DEFAULT)
    SENTENCE_MODEL: Optional[SentenceTransformer] = SentenceTransformer(EMBEDDING_MODEL_NAME)
    if SENTENCE_MODEL:
      EMBED_DIM = SENTENCE_MODEL.get_sentence_embedding_dimension()
    else:
      EMBED_DIM = 384
except ImportError:
    print("[WARN] 未安裝 sentence-transformers，將使用 SHA256 偽向量。建議安裝: pip install sentence-transformers")
    SENTENCE_MODEL = None
    EMBED_DIM = 384

# ────────────────────────────
# 全域組態（Config）
# ────────────────────────────
BASE_DIR = Path(os.getenv("LMS_HOME", Path(__file__).parent)).resolve()
DATA_DIR = BASE_DIR / "data"
LOG_STATE_FILE = DATA_DIR / "file_state.json"
VECTOR_DB_PATH = DATA_DIR / "faiss.index"

# 新增：日誌來源與結果匯出路徑設定
DEFAULT_TARGET_LOG_DIR = "/var/log/LMS_LOG"
DEFAULT_ANALYSIS_OUTPUT_FILE = "/var/log/analyzer_results.json"
DEFAULT_OPERATIONAL_LOG_FILE = BASE_DIR / "analyzer_script.log"

LMS_TARGET_LOG_DIR = Path(os.getenv("LMS_TARGET_LOG_DIR", DEFAULT_TARGET_LOG_DIR))
LMS_ANALYSIS_OUTPUT_FILE = Path(os.getenv("LMS_ANALYSIS_OUTPUT_FILE", DEFAULT_ANALYSIS_OUTPUT_FILE))
LMS_OPERATIONAL_LOG_FILE = Path(os.getenv("LMS_OPERATIONAL_LOG_FILE", str(DEFAULT_OPERATIONAL_LOG_FILE)))


CACHE_SIZE = int(os.getenv("LMS_CACHE_SIZE", 10_000))
SAMPLE_TOP_PERCENT = int(os.getenv("LMS_SAMPLE_TOP_PERCENT", 20))
BATCH_SIZE = int(os.getenv("LMS_LLM_BATCH_SIZE", 10))
MAX_HOURLY_COST_USD = float(os.getenv("LMS_MAX_HOURLY_COST_USD", 5.0))
PRICE_IN_PER_1K_TOKENS = float(os.getenv("LMS_PRICE_IN_PER_1K_TOKENS", 0.000125))
PRICE_OUT_PER_1K_TOKENS = float(os.getenv("LMS_PRICE_OUT_PER_1K_TOKENS", 0.000375))
SIM_T_ATTACK_L2_THRESHOLD = float(os.getenv("LMS_SIM_T_ATTACK_L2_THRESHOLD", 0.3))
SIM_N_NORMAL_L2_THRESHOLD = float(os.getenv("LMS_SIM_N_NORMAL_L2_THRESHOLD", 0.2))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_ENABLED = bool(GEMINI_API_KEY and ChatGoogleGenerativeAI)
LLM_MODEL_NAME = os.getenv("LMS_LLM_MODEL_NAME", "gemini-1.5-flash-latest")

DATA_DIR.mkdir(parents=True, exist_ok=True)
# 確保匯出結果的目錄存在 (如果不是 /var/log/ 這種通常已存在的目錄)
if LMS_ANALYSIS_OUTPUT_FILE.parent != Path("/var/log"): # /var/log 通常存在
    LMS_ANALYSIS_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
if LMS_OPERATIONAL_LOG_FILE.parent != Path("/var/log"):
    LMS_OPERATIONAL_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


# ────────────────────────────
# 日誌記錄設定 (Logging Setup)
# ────────────────────────────
log_handlers: List[logging.Handler] = [logging.StreamHandler(sys.stdout)]
try:
    file_handler = logging.FileHandler(LMS_OPERATIONAL_LOG_FILE, encoding='utf-8')
    log_handlers.append(file_handler)
except PermissionError:
    print(f"[CRITICAL] 無權限寫入運維日誌檔案 {LMS_OPERATIONAL_LOG_FILE}。請檢查權限或更改 LMS_OPERATIONAL_LOG_FILE 環境變數。")
    # 如果無法寫入運維日誌，至少確保控制台輸出可用

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
    handlers=log_handlers
)
logger = logging.getLogger(__name__)


# ... (其餘程式碼與前一版大部分相同，此處省略以節省篇幅) ...
# 以下是 embed, VectorIndex, LRUCache, LLM Setup, FileState, load_state, save_state,
# open_log, tail_since, SUSPICIOUS_KEYWORDS, parse_status, response_time, fast_score,
# LLMCostTracker, llm_analyse 這些函式/類別的定義。
# 假設它們都和您提供的 "advanced_log_analyzer_v2.py" 版本一致。
# 為了簡潔，我將直接跳到 process_logs 和 if __name__ == "__main__": 的修改部分。

# < Начало пропущенного кода >
# ────────────────────────────
# Embedding 工具
# ────────────────────────────
def embed(text: str) -> List[float]:
    """
    產生嵌入向量。
    優先使用 SentenceTransformer 模型，若未安裝則退回使用 SHA-256 偽向量。
    【【警告】】SHA-256 偽向量僅供示範與無真實模型時的相容性，無法用於實際相似度分析！
    請務必安裝 sentence-transformers 並選擇合適的模型，或替換為其他 embedding API。
    """
    if SENTENCE_MODEL:
        embedding_vector = SENTENCE_MODEL.encode(text, convert_to_numpy=True) # type: ignore
        return embedding_vector.tolist()

    logger.warning("正在使用 SHA-256 偽向量，這不適用於生產環境！請安裝真實的 embedding 模型。")
    digest = hashlib.sha256(text.encode('utf-8', 'replace')).digest()
    vec_template = list(digest)
    vec = []
    while len(vec) < EMBED_DIM:
        vec.extend(vec_template)
    return [v / 255.0 for v in vec[:EMBED_DIM]]

# ────────────────────────────
# FAISS 向量索引包裝
# ────────────────────────────
class VectorIndex:
    """封裝 FAISS Index 的簡易類別，包含自動載入 / 保存。"""
    def __init__(self, path: Path, dimension: int):
        self.path = path
        self.dimension = dimension
        self.index: Optional[faiss.Index] = None # type: ignore
        self._load()

    def _load(self):
        if faiss is None:
            logger.warning("Faiss 未安裝，向量索引功能停用。")
            return
        if self.path.exists():
            try:
                self.index = faiss.read_index(str(self.path))
                logger.info(f"從 {self.path} 載入 FAISS 索引，共 {self.index.ntotal if self.index else 0} 個向量。")
            except Exception as e:
                logger.error(f"讀取 FAISS 索引失敗: {e}。將建立新索引。")
                self.index = faiss.IndexFlatL2(self.dimension)
        else:
            logger.info(f"未找到 FAISS 索引檔 {self.path}，建立新的 L2 索引 (維度: {self.dimension})。")
            self.index = faiss.IndexFlatL2(self.dimension)

    def save(self):
        if faiss and self.index is not None:
            try:
                faiss.write_index(self.index, str(self.path))
                logger.info(f"FAISS 索引已儲存至 {self.path} ({self.index.ntotal} 個向量)。")
            except Exception as e:
                logger.error(f"儲存 FAISS 索引失敗: {e}")


    def search(self, vec: List[float], k: int = 5) -> Tuple[List[int], List[float]]:
        """回傳 (ids, dists)。若索引為空則回傳空列表。"""
        import numpy as np
        if faiss is None or self.index is None or self.index.ntotal == 0:
            return [], []
        query_vector = np.array([vec], dtype=np.float32)
        dists, ids = self.index.search(query_vector, k)
        return ids[0].tolist(), dists[0].tolist()

    def add(self, vecs: List[List[float]]):
        import numpy as np
        if faiss and self.index is not None:
            vectors_to_add = np.array(vecs, dtype=np.float32)
            self.index.add(vectors_to_add)
            logger.debug(f"新增 {len(vecs)} 個向量到 FAISS 索引。目前總數: {self.index.ntotal}")

VECTOR_DB = VectorIndex(VECTOR_DB_PATH, EMBED_DIM)

# ────────────────────────────
# LRU Cache – 快取 LLM 結果降低成本
# ────────────────────────────
class LRUCache(OrderedDict):
    def __init__(self, capacity: int):
        super().__init__()
        self.capacity = capacity

    def get(self, key: Any) -> Optional[Any]: # type: ignore
        if key in self:
            self.move_to_end(key)
            return self[key]
        return None

    def put(self, key: Any, value: Any): # type: ignore
        if key in self:
            self.move_to_end(key)
        self[key] = value
        if len(self) > self.capacity:
            self.popitem(last=False)

CACHE = LRUCache(CACHE_SIZE)

# ────────────────────────────
# Gemini / LLM 包裝
# ────────────────────────────
LLM_CHAIN: Optional[Runnable] = None
if GEMINI_ENABLED and ChatGoogleGenerativeAI and PromptTemplate:
    try:
        llm = ChatGoogleGenerativeAI(
            model=LLM_MODEL_NAME,
            google_api_key=GEMINI_API_KEY,
            temperature=0.3,
            convert_system_message_to_human=True,
        )
        PROMPT_TEMPLATE_STR = """
System: 你是一位資安分析助手。請仔細評估以下 Web 伺服器日誌條目，判斷其是否顯示任何潛在的攻擊行為、可疑活動或明顯的錯誤。
你的分析應著重於識別模式，例如 SQL注入、跨站腳本(XSS)、目錄遍歷、機器人掃描、暴力破解嘗試、異常的 User-Agent、非預期的 HTTP 狀態碼、過長的請求或回應時間等。

請根據你的分析，提供一個 JSON 格式的回應，包含以下欄位：
- "is_attack": boolean (如果日誌條目指示了攻擊或高度可疑行為，則為 true)
- "attack_type": string (如果 is_attack 為 true，請描述攻擊類型，例如 "SQL Injection", "XSS", "Path Traversal", "Bot Scanning", "Error Exploitation", "Unknown Anomaly"。如果 is_attack 為 false，則為 "N/A")
- "reason": string (簡要解釋你判斷的理由，即使 is_attack 為 false 也請說明為何正常或僅為低風險錯誤)
- "severity": string (攻擊的嚴重程度，例如 "High", "Medium", "Low"。如果 is_attack 為 false，則為 "None")

Log Entry:
{log_entry}

JSON Output:
"""
        PROMPT = PromptTemplate(
            input_variables=["log_entry"],
            template=PROMPT_TEMPLATE_STR
        )
        LLM_CHAIN = PROMPT | llm # type: ignore
        logger.info(f"LLM ({LLM_MODEL_NAME}) 初始化完成。")
    except Exception as e:
        logger.error(f"LLM 初始化失敗: {e}")
        GEMINI_ENABLED = False
        LLM_CHAIN = None
else:
    logger.warning("Gemini LLM 未啟用 (API Key 或 LangChain/Google GenAI 函式庫缺失)。")
    LLM_CHAIN = None

# ────────────────────────────
# 檔案狀態（inode / offset）持久化
# ────────────────────────────
FileState = Dict[str, Dict[str, Any]]

def load_state() -> FileState:
    if LOG_STATE_FILE.exists():
        try:
            state = json.loads(LOG_STATE_FILE.read_text(encoding='utf-8'))
            logger.info(f"從 {LOG_STATE_FILE} 載入檔案狀態。")
            return state
        except json.JSONDecodeError as e:
            logger.error(f"解析檔案狀態檔 {LOG_STATE_FILE} 失敗: {e}。將使用空狀態。")
            return {}
        except Exception as e:
            logger.error(f"載入檔案狀態檔 {LOG_STATE_FILE} 時發生未知錯誤: {e}。將使用空狀態。")
            return {}
    logger.info(f"未找到檔案狀態檔 {LOG_STATE_FILE}，將使用空狀態。")
    return {}

def save_state(state: FileState):
    try:
        LOG_STATE_FILE.write_text(json.dumps(state, indent=2), encoding='utf-8')
        logger.info(f"檔案狀態已儲存至 {LOG_STATE_FILE}。")
    except Exception as e:
        logger.error(f"儲存檔案狀態至 {LOG_STATE_FILE} 失敗: {e}")

STATE = load_state()

# ────────────────────────────
# 工具函式
# ────────────────────────────
def open_log(path: Path) -> io.BufferedReader:
    if path.suffix == ".gz":
        return gzip.open(path, "rb") # type: ignore
    if path.suffix == ".bz2":
        return bz2.open(path, "rb") # type: ignore
    return path.open("rb")

def tail_since(path: Path) -> List[str]:
    try:
        inode = path.stat().st_ino
    except FileNotFoundError:
        logger.warning(f"日誌檔案 {path} 不存在，跳過處理。")
        return []

    file_key = str(path.resolve())
    stored = STATE.get(file_key, {"inode": inode, "offset": 0})

    if stored["inode"] != inode:
        logger.info(f"日誌檔案 {path} inode 發生變化 (從 {stored['inode']} 到 {inode})，視為新檔案並從頭讀取。")
        stored = {"inode": inode, "offset": 0}

    new_lines: List[str] = []
    try:
        with open_log(path) as f:
            f.seek(stored["offset"])
            line_bytes: bytes
            for line_bytes in f:
                try:
                    new_lines.append(line_bytes.decode("utf-8").rstrip())
                except UnicodeDecodeError:
                    decoded_line = line_bytes.decode("utf-8", "replace").rstrip()
                    logger.warning(
                        f"檔案 {path} 中存在 Unicode 解碼錯誤。已使用 'replace' 策略處理。問題行 (部分): {decoded_line[:100]}"
                    )
                    new_lines.append(decoded_line)
            stored["offset"] = f.tell()
    except FileNotFoundError:
         logger.warning(f"讀取日誌檔案 {path} 時，檔案突然消失。")
         return []
    except Exception as e:
        logger.error(f"讀取日誌檔案 {path} 失敗: {e}")
        return []

    STATE[file_key] = stored
    if new_lines:
        logger.info(f"從 {path} 讀取到 {len(new_lines)} 行新日誌。目前 offset: {stored['offset']}")
    return new_lines

# ────────────────────────────
# 快速啟發式評分（不耗 LLM）
# ────────────────────────────
SUSPICIOUS_KEYWORDS = ["/etc/passwd", "<script>", " OR ", "%20OR%20", "SELECT ", "UNION ", "INSERT ", "CONCAT("]

def parse_status(line: str) -> int:
    try:
        parts = line.split("\"")
        if len(parts) > 2:
             status_part = parts[2].strip().split()[0]
             return int(status_part)
    except Exception:
        pass
    return 0

def response_time(line: str) -> float:
    if "resp_time:" in line:
        try:
            val_str = line.split("resp_time:")[1].split()[0].split("\"")[0]
            return float(val_str)
        except (ValueError, IndexError):
            pass
    return 0.0

def fast_score(line: str) -> float:
    score = 0.0
    status = parse_status(line)
    if not 200 <= status < 400 and status != 0:
        score += 0.4
    if response_time(line) > 1.0:
        score += 0.2
    lp = line.lower()
    keyword_hits = sum(1 for k in SUSPICIOUS_KEYWORDS if k.lower() in lp)
    if keyword_hits > 0:
        score += min(0.4, keyword_hits * 0.1)
    common_scanner_uas = ["nmap", "sqlmap", "nikto", "curl/", "python-requests"]
    if any(ua.lower() in lp for ua in common_scanner_uas):
        score += 0.2
    return min(score, 1.0)

# ────────────────────────────
# LLM 成本追蹤與分析流程
# ────────────────────────────
class LLMCostTracker:
    def __init__(self):
        self.in_tokens_hourly = 0
        self.out_tokens_hourly = 0
        self.cost_hourly = 0.0
        self.total_in_tokens = 0
        self.total_out_tokens = 0
        self.total_cost = 0.0
        self._window_start_time = datetime.now(timezone.utc)

    def add_usage(self, in_tok: int, out_tok: int):
        self.in_tokens_hourly += in_tok
        self.out_tokens_hourly += out_tok
        current_cost = (in_tok / 1000 * PRICE_IN_PER_1K_TOKENS) + \
                       (out_tok / 1000 * PRICE_OUT_PER_1K_TOKENS)
        self.cost_hourly += current_cost
        self.total_in_tokens += in_tok
        self.total_out_tokens += out_tok
        self.total_cost += current_cost

    def reset_if_window_passed(self):
        if datetime.now(timezone.utc) - self._window_start_time > timedelta(hours=1):
            logger.info(
                f"LLM 每小時費用窗口重置。上一小時: "
                f"Input Tokens: {self.in_tokens_hourly}, Output Tokens: {self.out_tokens_hourly}, Cost: ${self.cost_hourly:.4f}"
            )
            self.in_tokens_hourly = 0
            self.out_tokens_hourly = 0
            self.cost_hourly = 0.0
            self._window_start_time = datetime.now(timezone.utc)
    def get_hourly_cost(self) -> float:
        return self.cost_hourly
    def get_total_stats(self) -> dict:
        return {
            "total_input_tokens": self.total_in_tokens,
            "total_output_tokens": self.total_out_tokens,
            "total_cost_usd": self.total_cost
        }
COST_TRACKER = LLMCostTracker()

def llm_analyse(lines: List[str]) -> List[Optional[dict]]:
    if not LLM_CHAIN:
        logger.warning("LLM 未啟用，跳過分析。")
        return [None] * len(lines)

    results: List[Optional[dict]] = [None] * len(lines)
    original_indices_to_query: List[int] = []
    batch_inputs: List[Dict[str, str]] = []

    for idx, line_content in enumerate(lines):
        cached_result = CACHE.get(line_content)
        if cached_result is not None:
            results[idx] = cached_result
            logger.debug(f"快取命中: {line_content[:100]}...")
        else:
            original_indices_to_query.append(idx)
            batch_inputs.append({"log_entry": line_content})

    if not batch_inputs:
        logger.info("所有待分析日誌均命中快取。")
        return results

    COST_TRACKER.reset_if_window_passed()
    if COST_TRACKER.get_hourly_cost() >= MAX_HOURLY_COST_USD:
        logger.warning(f"已達每小時 LLM 費用上限 (${MAX_HOURLY_COST_USD:.2f})，本輪剩餘日誌將不進行分析。")
        for i_orig in original_indices_to_query:
             results[i_orig] = {"is_attack": False, "attack_type": "N/A", "reason": "Budget limit reached, not analyzed.", "severity": "None"}
        return results
    
    logger.info(f"準備批次呼叫 LLM 分析 {len(batch_inputs)} 筆日誌 (快取未命中部分)。")
    try:
        llm_responses = LLM_CHAIN.batch(batch_inputs, config={"max_concurrency": 5}) # type: ignore
        total_in_tokens_batch = 0
        total_out_tokens_batch = 0

        for i, response_content_str in enumerate(llm_responses):
            original_idx = original_indices_to_query[i]
            log_line_for_cache = lines[original_idx]
            actual_content = response_content_str
            if hasattr(response_content_str, 'content'):
                 actual_content = response_content_str.content # type: ignore
            if hasattr(response_content_str, 'text'):
                 actual_content = response_content_str.text # type: ignore

            try:
                analysis_result = json.loads(actual_content) # type: ignore
                results[original_idx] = analysis_result
                CACHE.put(log_line_for_cache, analysis_result)
                prompt_str = PROMPT.format(log_entry=log_line_for_cache) # type: ignore
                in_tok_approx = len(prompt_str.split())
                out_tok_approx = len(actual_content.split())
                total_in_tokens_batch += in_tok_approx
                total_out_tokens_batch += out_tok_approx
            except json.JSONDecodeError as json_e:
                logger.error(f"LLM 回應 JSON 解析失敗 for log '{log_line_for_cache[:100]}...': {json_e}")
                logger.debug(f"原始 LLM 回應: {actual_content}")
                error_analysis = {"is_attack": True, "attack_type": "LLM Data Error", "reason": f"LLM response parsing error: {json_e}. Original: {str(actual_content)[:100]}...", "severity": "Medium"}
                results[original_idx] = error_analysis
                CACHE.put(log_line_for_cache, error_analysis)
            except Exception as e_inner:
                logger.error(f"處理 LLM 回應時發生未知錯誤 for log '{log_line_for_cache[:100]}...': {e_inner}")
                error_analysis = {"is_attack": True, "attack_type": "LLM Processing Error", "reason": f"LLM response processing error: {e_inner}", "severity": "Medium"}
                results[original_idx] = error_analysis
                CACHE.put(log_line_for_cache, error_analysis)
        
        COST_TRACKER.add_usage(total_in_tokens_batch, total_out_tokens_batch)
        logger.info(f"LLM 批次呼叫完成。Input tokens (approx): {total_in_tokens_batch}, Output tokens (approx): {total_out_tokens_batch}")

    except Exception as e_outer:
        logger.error(f"LLM 批次呼叫失敗: {e_outer}", exc_info=True)
        for i_orig in original_indices_to_query:
            if results[i_orig] is None:
                log_line_for_cache = lines[i_orig]
                error_analysis = {"is_attack": True, "attack_type": "LLM API Error", "reason": f"LLM batch API call failed: {e_outer}", "severity": "High"}
                results[i_orig] = error_analysis
                CACHE.put(log_line_for_cache, error_analysis)

    if COST_TRACKER.get_hourly_cost() >= MAX_HOURLY_COST_USD:
        logger.warning(f"LLM 處理後已達或超過每小時費用上限 (${MAX_HOURLY_COST_USD:.2f})。")
    return results
# < Конец пропущенного кода >

# ────────────────────────────
# 主流程（單次執行）
# ────────────────────────────

def process_logs(log_paths: List[Path]):
    """主處理函式：
    1. 收集新日誌
    2. 快速打分並抽樣
    3. 更新向量索引 (針對抽樣後的高分日誌)
    4. (可選演示) 使用 FAISS 搜尋相似日誌並初步判斷
    5. 呼叫 LLM 分析 (針對抽樣後的高分日誌)
    6. 輸出警示至運維日誌並彙整結果以供匯出
    7. 持久化狀態
    8. 回傳彙整的分析結果
    """
    # 1) 讀取增量日誌
    all_new_lines: List[str] = []
    for p in log_paths:
        if not p.exists():
            logger.warning(f"指定的日誌路徑 {p} 不存在，跳過。")
            continue
        if not p.is_file():
            logger.warning(f"指定的日誌路徑 {p} 不是一個檔案，跳過。")
            continue
        all_new_lines.extend(tail_since(p))

    if not all_new_lines:
        logger.info("無新增日誌需要處理。")
        # 即使沒有分析，也要保存 offset 和可能的 FAISS 索引變更
        save_state(STATE)
        VECTOR_DB.save()
        return [] # 回傳空列表表示沒有結果可匯出

    logger.info(f"共收到 {len(all_new_lines)} 行新日誌。")

    # 2) 快速評分，取前 N% 或至少一個（如果分數大於0）
    scored_lines = [(fast_score(line), line) for line in all_new_lines]
    scored_lines.sort(key=lambda x: x[0], reverse=True)
    num_to_sample = max(1, int(len(scored_lines) * SAMPLE_TOP_PERCENT / 100))
    top_scored_lines_with_scores = [sl for sl in scored_lines if sl[0] > 0.0][:num_to_sample]

    if not top_scored_lines_with_scores:
        logger.info("所有新日誌的啟發式評分均為0，或抽樣後無日誌，無需進一步分析。")
        save_state(STATE)
        VECTOR_DB.save()
        return []

    top_lines_content = [line_content for _, line_content in top_scored_lines_with_scores]
    logger.info(f"啟發式評分後，選出 {len(top_lines_content)} 行日誌進行深度分析 (最高分: {top_scored_lines_with_scores[0][0]:.2f})。")

    # 3) 建立 Embedding 並更新向量索引
    line_embeddings: List[List[float]] = []
    if faiss and VECTOR_DB.index is not None:
        try:
            line_embeddings = [embed(line) for line in top_lines_content]
            if line_embeddings:
                VECTOR_DB.add(line_embeddings)
                logger.info(f"已為 {len(line_embeddings)} 行高分日誌產生 embedding 並存入 FAISS。")
        except Exception as e:
            logger.error(f"產生 embedding 或存入 FAISS 時發生錯誤: {e}", exc_info=True)
    else:
        logger.warning("FAISS 未啟用或索引未初始化，跳過 embedding 和向量索引更新。")

    # 4) (可選演示) FAISS 相似度搜尋
    if faiss and VECTOR_DB.index is not None and VECTOR_DB.index.ntotal > len(line_embeddings) and line_embeddings:
        logger.info("對新增的高分日誌進行 FAISS 相似度搜尋演示...")
        for i, (score, line) in enumerate(top_scored_lines_with_scores):
            if i < len(line_embeddings):
                current_vec = line_embeddings[i]
                ids, dists = VECTOR_DB.search(current_vec, k=3)
                if ids:
                    logger.info(f"日誌 (FastScore: {score:.2f}): \"{line[:100]}...\"")
                    for neighbor_id, dist in zip(ids, dists):
                        similarity_type = "未知"
                        if dist < SIM_T_ATTACK_L2_THRESHOLD:
                            similarity_type = f"高度相似於潛在攻擊模式 (L2距離: {dist:.4f})"
                        elif dist < SIM_N_NORMAL_L2_THRESHOLD:
                             similarity_type = f"高度相似於已知正常模式 (L2距離: {dist:.4f})"
                        else:
                            similarity_type = f"中/低度相似 (L2距離: {dist:.4f})"
                        logger.info(f"  -> FAISS Neighbor ID: {neighbor_id}, L2 Distance: {dist:.4f} ({similarity_type})")

    # 5) LLM 分析
    llm_analyses: List[Optional[dict]] = []
    if GEMINI_ENABLED and LLM_CHAIN:
        logger.info(f"開始使用 LLM 分析 {len(top_lines_content)} 行日誌...")
        llm_analyses = llm_analyse(top_lines_content)
    else:
        logger.warning("LLM 功能未啟用，跳過 LLM 分析。")
        llm_analyses = [{"is_attack": False, "attack_type": "N/A", "reason": "LLM disabled, not analyzed.", "severity": "None"} for _ in top_lines_content]

    # 6) 彙整結果供匯出，並同時輸出警示至運維日誌
    exported_results: List[Dict[str, Any]] = []
    alerts_found = 0
    logger.info("=" * 30 + " 分析結果 (部分將記錄於運維日誌) " + "=" * 30)
    for i, analysis_result in enumerate(llm_analyses):
        original_line = top_lines_content[i]
        fast_s = top_scored_lines_with_scores[i][0]

        current_export_item: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "original_log": original_line,
            "fast_score": float(f"{fast_s:.2f}"), # 確保為 float
            "llm_analysis": analysis_result
        }
        exported_results.append(current_export_item)

        if analysis_result:
            is_attack = analysis_result.get("is_attack", False)
            attack_type = analysis_result.get("attack_type", "N/A")
            reason = analysis_result.get("reason", "No reason provided.")
            severity = analysis_result.get("severity", "None")

            log_message = ( # 這是運維日誌的輸出
                f"日誌: {original_line}\n"
                f"  ├─ 啟發式評分: {fast_s:.2f}\n"
                f"  ├─ LLM 分析:\n"
                f"  │  ├─ 是否攻擊: {is_attack}\n"
                f"  │  ├─ 攻擊類型: {attack_type}\n"
                f"  │  ├─ 分析原因: {reason}\n"
                f"  │  └─ 嚴重等級: {severity}\n"
                f"  └─原始LLM JSON: {json.dumps(analysis_result, ensure_ascii=False)}"
            )
            if is_attack:
                logger.warning(log_message)
                alerts_found +=1
            else:
                logger.info(log_message)
        else:
            logger.info(f"日誌: {original_line}\n  ├─ 啟發式評分: {fast_s:.2f}\n  └─ LLM 分析: 未執行或無結果。")
    logger.info("=" * (78)) # 等長線

    if alerts_found > 0:
        logger.warning(f"分析完成，共發現 {alerts_found} 個潛在攻擊警示 (詳見運維日誌)。")
    else:
        logger.info("分析完成，未發現明確的攻擊警示 (基於 LLM 分析結果，詳見運維日誌)。")

    # 7) 持久化狀態
    save_state(STATE)
    VECTOR_DB.save()
    logger.info(f"總 LLM 使用情況: {COST_TRACKER.get_total_stats()}")

    # 8) 回傳彙整的分析結果
    return exported_results


# ────────────────────────────
# 主執行入口
# ────────────────────────────
if __name__ == "__main__":
    logger.info(f"進階日誌分析器啟動... 目標日誌目錄: {LMS_TARGET_LOG_DIR}, 結果匯出檔案: {LMS_ANALYSIS_OUTPUT_FILE}")
    logger.info(f"運維日誌將輸出至控制台及檔案: {LMS_OPERATIONAL_LOG_FILE}")

    if not GEMINI_API_KEY:
        logger.error("錯誤：環境變數 GEMINI_API_KEY 未設定。LLM 功能將停用。")
    if not ChatGoogleGenerativeAI: # Redundant if GEMINI_ENABLED check is primary
        logger.error("錯誤：LangChain 或 Google GenAI 相關函式庫未正確載入。LLM 功能將停用。")
    if not faiss:
        logger.warning("警告：FAISS 函式庫未載入。向量搜尋功能將停用。")

    # 從目標目錄讀取日誌檔案列表
    log_file_paths_to_process: List[Path] = []
    if LMS_TARGET_LOG_DIR.exists() and LMS_TARGET_LOG_DIR.is_dir():
        logger.info(f"正在掃描日誌目錄: {LMS_TARGET_LOG_DIR}")
        for item in LMS_TARGET_LOG_DIR.iterdir():
            # 僅處理特定後綴的檔案，且確定是檔案而非子目錄
            if item.is_file() and item.suffix.lower() in [".log", ".gz", ".bz2"]:
                log_file_paths_to_process.append(item)
        if not log_file_paths_to_process:
            logger.info(f"在 {LMS_TARGET_LOG_DIR} 中未找到符合條件 (.log, .gz, .bz2) 的日誌檔案。")
        else:
            logger.info(f"將處理以下日誌檔案: {[str(p) for p in log_file_paths_to_process]}")
    else:
        logger.warning(f"目標日誌目錄 {LMS_TARGET_LOG_DIR} 不存在或不是一個目錄。請建立該目錄並放入日誌檔案，或更改 LMS_TARGET_LOG_DIR 環境變數。")

    # 執行處理流程
    all_exported_data: List[Dict[str, Any]] = []
    if log_file_paths_to_process: # 僅當有檔案處理時才執行
        try:
            all_exported_data = process_logs(log_file_paths_to_process)
        except Exception as main_e:
            logger.critical(f"主處理流程發生未預期錯誤: {main_e}", exc_info=True)
    else:
        logger.info("沒有日誌檔案需要處理，跳過主流程。")


    # 在程式結束前儲存狀態和索引 (無論是否有處理新日誌)
    # 並匯出本次執行的分析結果 (如果有)
    try:
        logger.info("程式即將結束，儲存最終狀態...")
        save_state(STATE) # STATE 可能因為 tail_since 即使無新日誌但 inode 變化而更新
        VECTOR_DB.save()

        if all_exported_data:
            try:
                with open(LMS_ANALYSIS_OUTPUT_FILE, "w", encoding="utf-8") as f_out:
                    json.dump(all_exported_data, f_out, ensure_ascii=False, indent=2)
                logger.info(f"本次執行的結構化分析結果已匯出至 {LMS_ANALYSIS_OUTPUT_FILE} ({len(all_exported_data)} 筆記錄)")
            except PermissionError:
                logger.critical(f"無權限寫入分析結果檔案 {LMS_ANALYSIS_OUTPUT_FILE}。請檢查權限或更改 LMS_ANALYSIS_OUTPUT_FILE 環境變數。")
            except Exception as e_export:
                logger.error(f"匯出分析結果至 {LMS_ANALYSIS_OUTPUT_FILE} 失敗: {e_export}", exc_info=True)
        else:
            logger.info("本次執行沒有產生新的可匯出的結構化分析結果。")

    except Exception as final_save_e:
        logger.error(f"結束前儲存狀態或索引時發生錯誤: {final_save_e}", exc_info=True)
    finally:
        logger.info(f"最終 LLM 總使用統計: {COST_TRACKER.get_total_stats()}")
        logger.info("進階日誌分析器執行完畢。")