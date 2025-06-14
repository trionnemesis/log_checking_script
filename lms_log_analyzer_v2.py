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

DEFAULT_TARGET_LOG_DIR = "/var/log/LMS_LOG/" #
DEFAULT_ANALYSIS_OUTPUT_FILE = "/var/log/analyzer_results.json"
DEFAULT_OPERATIONAL_LOG_FILE = BASE_DIR / "analyzer_script.log"

LMS_TARGET_LOG_DIR = Path(os.getenv("LMS_TARGET_LOG_DIR", DEFAULT_TARGET_LOG_DIR))
LMS_ANALYSIS_OUTPUT_FILE = Path(os.getenv("LMS_ANALYSIS_OUTPUT_FILE", DEFAULT_ANALYSIS_OUTPUT_FILE))
LMS_OPERATIONAL_LOG_FILE = Path(os.getenv("LMS_OPERATIONAL_LOG_FILE", str(DEFAULT_OPERATIONAL_LOG_FILE)))

CACHE_SIZE = int(os.getenv("LMS_CACHE_SIZE", 10_000))
SAMPLE_TOP_PERCENT = int(os.getenv("LMS_SAMPLE_TOP_PERCENT", 10))
BATCH_SIZE = int(os.getenv("LMS_LLM_BATCH_SIZE", 10))
MAX_HOURLY_COST_USD = float(os.getenv("LMS_MAX_HOURLY_COST_USD", 5.0)) #
PRICE_IN_PER_1K_TOKENS = float(os.getenv("LMS_PRICE_IN_PER_1K_TOKENS", 0.000125))
PRICE_OUT_PER_1K_TOKENS = float(os.getenv("LMS_PRICE_OUT_PER_1K_TOKENS", 0.000375))

# --- 向量搜尋過濾閾值設定 ---
# 攻擊模式相似度閾值：L2距離小於此值，視為與已知攻擊高度相似。
SIM_T_ATTACK_L2_THRESHOLD = float(os.getenv("LMS_SIM_T_ATTACK_L2_THRESHOLD", 0.3))
# 正常模式相似度閾值：L2距離小於此值，視為與已知正常模式高度相似。
SIM_N_NORMAL_L2_THRESHOLD = float(os.getenv("LMS_SIM_N_NORMAL_L2_THRESHOLD", 0.2))
# 新穎性判斷閾值：L2距離大於此值，視為一個全新的、未見過的模式。
NOVELTY_L2_THRESHOLD = float(os.getenv("LMS_NOVELTY_L2_THRESHOLD", 0.5))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") #
GEMINI_ENABLED = bool(GEMINI_API_KEY and ChatGoogleGenerativeAI)
LLM_MODEL_NAME = os.getenv("LMS_LLM_MODEL_NAME", "gemini-1.5-flash-latest")

DATA_DIR.mkdir(parents=True, exist_ok=True)
if LMS_ANALYSIS_OUTPUT_FILE.parent != Path("/var/log"):
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
    handlers=log_handlers
)
logger = logging.getLogger(__name__)

# ────────────────────────────
# Embedding 工具
# ────────────────────────────
def embed(text: str) -> List[float]:
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
            return json.loads(LOG_STATE_FILE.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"載入或解析檔案狀態檔 {LOG_STATE_FILE} 失敗: {e}。將使用空狀態。")
            return {}
    return {}
def save_state(state: FileState):
    try:
        LOG_STATE_FILE.write_text(json.dumps(state, indent=2), encoding='utf-8')
    except Exception as e:
        logger.error(f"儲存檔案狀態至 {LOG_STATE_FILE} 失敗: {e}")
STATE = load_state()

# ────────────────────────────
# 工具函式
# ────────────────────────────
def open_log(path: Path) -> io.BufferedReader:
    if path.suffix == ".gz": return gzip.open(path, "rb") # type: ignore
    if path.suffix == ".bz2": return bz2.open(path, "rb") # type: ignore
    return path.open("rb")
def tail_since(path: Path) -> List[str]:
    try: inode = path.stat().st_ino
    except FileNotFoundError: return []
    file_key = str(path.resolve())
    stored = STATE.get(file_key, {"inode": inode, "offset": 0})
    if stored["inode"] != inode:
        logger.info(f"日誌檔案 {path} inode 發生變化，從頭讀取。")
        stored = {"inode": inode, "offset": 0}
    new_lines: List[str] = []
    try:
        with open_log(path) as f:
            f.seek(stored["offset"])
            for line_bytes in f:
                try: new_lines.append(line_bytes.decode("utf-8").rstrip())
                except UnicodeDecodeError:
                    new_lines.append(line_bytes.decode("utf-8", "replace").rstrip())
            stored["offset"] = f.tell()
    except Exception as e:
        logger.error(f"讀取日誌檔案 {path} 失敗: {e}")
        return []
    STATE[file_key] = stored
    return new_lines

# ────────────────────────────
# 快速啟發式評分（不耗 LLM）
# ────────────────────────────
SUSPICIOUS_KEYWORDS = ["/etc/passwd", "<script>", " OR ", "%20OR%20", "SELECT ", "UNION ", "INSERT ", "CONCAT("]
def parse_status(line: str) -> int:
    try:
        return int(line.split("\"")[2].strip().split()[0])
    except Exception: return 0
def response_time(line: str) -> float:
    if "resp_time:" in line:
        try: return float(line.split("resp_time:")[1].split()[0].split("\"")[0])
        except (ValueError, IndexError): pass
    return 0.0
def fast_score(line: str) -> float:
    score = 0.0
    status = parse_status(line)
    if not 200 <= status < 400 and status != 0: score += 0.4
    if response_time(line) > 1.0: score += 0.2
    lp = line.lower()
    score += min(0.4, sum(1 for k in SUSPICIOUS_KEYWORDS if k.lower() in lp) * 0.1)
    if any(ua.lower() in lp for ua in ["nmap", "sqlmap", "nikto", "curl/", "python-requests"]):
        score += 0.2
    return min(score, 1.0)

# ────────────────────────────
# LLM 成本追蹤與分析流程
# ────────────────────────────
class LLMCostTracker:
    def __init__(self):
        self.in_tokens_hourly, self.out_tokens_hourly, self.cost_hourly = 0, 0, 0.0
        self.total_in_tokens, self.total_out_tokens, self.total_cost = 0, 0, 0.0
        self._window_start_time = datetime.now(timezone.utc)
    def add_usage(self, in_tok: int, out_tok: int):
        self.in_tokens_hourly += in_tok; self.out_tokens_hourly += out_tok
        cost = (in_tok / 1000 * PRICE_IN_PER_1K_TOKENS) + (out_tok / 1000 * PRICE_OUT_PER_1K_TOKENS)
        self.cost_hourly += cost; self.total_in_tokens += in_tok
        self.total_out_tokens += out_tok; self.total_cost += cost
    def reset_if_window_passed(self):
        if datetime.now(timezone.utc) - self._window_start_time > timedelta(hours=1):
            logger.info(f"LLM 每小時費用窗口重置。上一小時成本: ${self.cost_hourly:.4f}")
            self.in_tokens_hourly, self.out_tokens_hourly, self.cost_hourly = 0, 0, 0.0
            self._window_start_time = datetime.now(timezone.utc)
    def get_hourly_cost(self) -> float: return self.cost_hourly
    def get_total_stats(self) -> dict:
        return {"total_input_tokens": self.total_in_tokens, "total_output_tokens": self.total_out_tokens, "total_cost_usd": self.total_cost}
COST_TRACKER = LLMCostTracker()

def llm_analyse(lines: List[str]) -> List[Optional[dict]]:
    if not LLM_CHAIN: return [None] * len(lines)
    results: List[Optional[dict]] = [None] * len(lines)
    original_indices_to_query: List[int] = []
    batch_inputs: List[Dict[str, str]] = []
    for idx, line in enumerate(lines):
        if (cached := CACHE.get(line)) is not None:
            results[idx] = cached
        else:
            original_indices_to_query.append(idx)
            batch_inputs.append({"log_entry": line})
    if not batch_inputs: return results
    COST_TRACKER.reset_if_window_passed()
    if COST_TRACKER.get_hourly_cost() >= MAX_HOURLY_COST_USD:
        logger.warning(f"已達每小時 LLM 費用上限 (${MAX_HOURLY_COST_USD:.2f})，本輪剩餘日誌將不進行分析。")
        for i in original_indices_to_query:
             results[i] = {"is_attack": False, "attack_type": "N/A", "reason": "Budget limit reached", "severity": "None"}
        return results
    logger.info(f"準備批次呼叫 LLM 分析 {len(batch_inputs)} 筆日誌。")
    try:
        llm_responses = LLM_CHAIN.batch(batch_inputs, config={"max_concurrency": 5}) # type: ignore
        in_tok, out_tok = 0, 0
        for i, resp in enumerate(llm_responses):
            orig_idx = original_indices_to_query[i]
            line_cache_key = lines[orig_idx]
            try:
                content = getattr(resp, 'content', str(resp))
                analysis = json.loads(content)
                results[orig_idx] = analysis; CACHE.put(line_cache_key, analysis)
                in_tok += len(PROMPT.format(log_entry=line_cache_key).split())
                out_tok += len(content.split())
            except Exception as e:
                logger.error(f"LLM 回應解析失敗: {e}. Log: '{line_cache_key[:100]}...'", exc_info=True)
                err_res = {"is_attack": True, "attack_type": "LLM Error", "reason": f"LLM response error: {e}", "severity": "Medium"}
                results[orig_idx] = err_res; CACHE.put(line_cache_key, err_res)
        COST_TRACKER.add_usage(in_tok, out_tok)
    except Exception as e:
        logger.error(f"LLM 批次呼叫失敗: {e}", exc_info=True)
    return results

# ────────────────────────────
# 主流程（單次執行）
# ────────────────────────────
def process_logs(log_paths: List[Path]):
    """
    主處理函式（已優化，包含向量過濾層）：
    1. 收集新日誌。
    2. 快速打分並初步抽樣高分日誌。
    3. 對高分日誌進行向量化並更新向量索引。
    4. 【新增】執行向量過濾層，判斷哪些日誌是新穎的或與已知攻擊相似，以決定是否送交LLM。
    5. 聚合相似事件，僅選代表日誌送往 LLM 分析。
    6. 針對代表日誌呼叫 LLM，並將結果套用至同組日誌。
    7. 彙整所有來源（LLM、向量過濾器）的分析結果並匯出。
    """
    # 1. 收集所有指定路徑的新日誌
    all_new_lines = [line for p in log_paths if p.is_file() for line in tail_since(p)]
    if not all_new_lines:
        logger.info("無新增日誌需要處理。"); save_state(STATE); VECTOR_DB.save()
        return []

    # 2. 啟發式評分與抽樣
    scored_lines = sorted([(fast_score(line), line) for line in all_new_lines], key=lambda x: x[0], reverse=True)
    num_to_sample = max(1, int(len(scored_lines) * SAMPLE_TOP_PERCENT / 100))
    top_scored_lines_with_scores = [sl for sl in scored_lines if sl[0] > 0.0][:num_to_sample]
    if not top_scored_lines_with_scores:
        logger.info("所有新日誌啟發式評分過低，無需分析。"); save_state(STATE); VECTOR_DB.save()
        return []

    top_lines_content = [line for _, line in top_scored_lines_with_scores]
    logger.info(f"啟發式評分後，選出 {len(top_lines_content)} 行日誌進入向量分析階段。")

    # 3. 產生 Embedding 並更新向量索引
    line_embeddings = [embed(line) for line in top_lines_content] if faiss and VECTOR_DB.index is not None else []
    if line_embeddings: VECTOR_DB.add(line_embeddings)

    # 4. 【核心優化】基於向量相似度的過濾層
    logs_for_llm_analysis = []
    analysis_from_vector_filter = {} # 儲存被向量過濾器攔截的日誌的分析結果
    if faiss and VECTOR_DB.index is not None and VECTOR_DB.index.ntotal > 0 and line_embeddings:
        logger.info("執行向量過濾層，決定哪些日誌需要送交 LLM...")
        for i, (score, line) in enumerate(top_scored_lines_with_scores):
            if i >= len(line_embeddings): continue
            
            # 搜尋最接近的1個鄰居來判斷相似度
            ids, dists = VECTOR_DB.search(line_embeddings[i], k=1)
            min_dist = dists[0] if dists else float('inf')
            
            # 預設行為是將高分日誌送交LLM，除非被過濾規則攔截
            should_send_to_llm = True
            reason = "高分且模式新穎"

            if min_dist < NOVELTY_L2_THRESHOLD: # 如果與資料庫中某個模式足夠相似
                if min_dist < SIM_N_NORMAL_L2_THRESHOLD: # 且與已知「正常」模式高度相似
                    reason = f"與已知正常模式相似 (L2: {min_dist:.4f})，由向量過濾器攔截。"
                    should_send_to_llm = False
                    analysis_from_vector_filter[line] = {"is_attack": False, "reason": reason, "severity": "None", "source": "VectorFilter"}
                else: # 僅為一般已知模式，非高度可疑也非正常
                    reason = f"模式已存在於資料庫 (L2: {min_dist:.4f})，由向量過濾器攔截。"
                    should_send_to_llm = False
                    analysis_from_vector_filter[line] = {"is_attack": False, "reason": reason, "severity": "None", "source": "VectorFilter"}

            if min_dist < SIM_T_ATTACK_L2_THRESHOLD: # 無論如何，只要與已知「攻擊」模式高度相似，就必須送LLM確認
                reason = f"與已知攻擊模式高度相似 (L2: {min_dist:.4f})，送交LLM二次確認。"
                should_send_to_llm = True
                
            if should_send_to_llm:
                logs_for_llm_analysis.append(line)
                logger.info(f"選中日誌 (Score: {score:.2f}) -> LLM。原因: {reason}")
            else:
                logger.info(f"過濾日誌 (Score: {score:.2f})。原因: {reason}")
    else: # Fallback: 若向量索引不可用，則退回原策略
        logger.warning("FAISS 索引不可用，將所有高分日誌送交 LLM 分析。")
        logs_for_llm_analysis = top_lines_content

    # 5. 聚合相似事件，僅選代表日誌送往 LLM
    representative_lines: List[str] = []
    cluster_map: Dict[str, List[str]] = {}
    if faiss and VECTOR_DB.index is not None and logs_for_llm_analysis:
        for line in logs_for_llm_analysis:
            ids, _ = VECTOR_DB.search(embed(line), k=1)
            cluster_id = str(ids[0]) if ids else str(hash(line))
            if cluster_id not in cluster_map:
                cluster_map[cluster_id] = [line]
                representative_lines.append(line)
            else:
                cluster_map[cluster_id].append(line)
    else:
        for idx, line in enumerate(logs_for_llm_analysis):
            cid = str(idx)
            cluster_map[cid] = [line]
            representative_lines.append(line)

    # 6. LLM 分析 (僅對代表日誌呼叫)
    llm_analyses_map: Dict[str, Optional[dict]] = {}
    if GEMINI_ENABLED and LLM_CHAIN and representative_lines:
        llm_results_list = llm_analyse(representative_lines)
        for rep_line, analysis_result in zip(representative_lines, llm_results_list):
            if analysis_result:
                analysis_result["source"] = "LLM"
            for line_group in cluster_map.values():
                if rep_line in line_group:
                    for line in line_group:
                        llm_analyses_map[line] = analysis_result

    # 7. 彙整所有來源的結果並匯出
    exported_results: List[Dict[str, Any]] = []
    alerts_found = 0
    logger.info("=" * 30 + " 最終分析結果 " + "=" * 30)
    for fast_s, original_line in top_scored_lines_with_scores:
        # 優先取LLM的分析結果，若無，則取向量過濾器的分析結果
        analysis_result = llm_analyses_map.get(original_line, analysis_from_vector_filter.get(original_line))
        exported_results.append({
            "timestamp": datetime.now(timezone.utc).isoformat(), "original_log": original_line,
            "fast_score": float(f"{fast_s:.2f}"), "analysis": analysis_result
        })
        if analysis_result and analysis_result.get("is_attack"):
            logger.warning(f"【攻擊警示】來源: {analysis_result.get('source', 'N/A')}, 原因: {analysis_result.get('reason', 'N/A')}\n\t日誌: {original_line}")
            alerts_found += 1

    logger.info(f"分析完成，共發現 {alerts_found} 個潛在攻擊警示。")
    save_state(STATE); VECTOR_DB.save()
    logger.info(f"總 LLM 使用情況: {COST_TRACKER.get_total_stats()}")
    return exported_results

# ────────────────────────────
# 主執行入口
# ────────────────────────────
if __name__ == "__main__":
    logger.info(f"進階日誌分析器啟動... 目標日誌目錄: {LMS_TARGET_LOG_DIR}")
    if not GEMINI_API_KEY: logger.error("錯誤：環境變數 GEMINI_API_KEY 未設定。")
    
    log_file_paths = [p for p in LMS_TARGET_LOG_DIR.iterdir() if p.is_file() and p.suffix.lower() in [".log", ".gz", ".bz2"]] if LMS_TARGET_LOG_DIR.is_dir() else []

    if not log_file_paths:
        logger.warning(f"在 {LMS_TARGET_LOG_DIR} 中未找到任何日誌檔案。")
    else:
        logger.info(f"將處理以下日誌檔案: {[str(p.name) for p in log_file_paths]}")
        all_exported_data = []
        try:
            all_exported_data = process_logs(log_file_paths)
            if all_exported_data:
                try:
                    LMS_ANALYSIS_OUTPUT_FILE.write_text(json.dumps(all_exported_data, ensure_ascii=False, indent=2), encoding="utf-8")
                    logger.info(f"結構化分析結果已匯出至 {LMS_ANALYSIS_OUTPUT_FILE} ({len(all_exported_data)} 筆記錄)")
                except Exception as e:
                    logger.critical(f"無權限或無法寫入分析結果檔案 {LMS_ANALYSIS_OUTPUT_FILE}: {e}")
        except Exception as e:
            logger.critical(f"主處理流程發生未預期錯誤: {e}", exc_info=True)
    
    logger.info(f"最終 LLM 總使用統計: {COST_TRACKER.get_total_stats()}")
    logger.info("進階日誌分析器執行完畢。")
