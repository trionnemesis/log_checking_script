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
import re
import sys
import time
import logging
import signal
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed

# ────────────────────────────
# 第三方函式庫（請先安裝）
# ────────────────────────────
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
    # 延遲載入模型，避免啟動時間過長
    SENTENCE_MODEL: Optional[SentenceTransformer] = None
    EMBED_DIM = 384
except ImportError:
    print("[WARN] 未安裝 sentence-transformers，將使用 SHA256 偽向量。建議安裝: pip install sentence-transformers")
    SENTENCE_MODEL = None
    EMBED_DIM = 384

# ────────────────────────────
# 優化後的全域組態
# ────────────────────────────
BASE_DIR = Path(os.getenv("LMS_HOME", Path(__file__).parent)).resolve()
DATA_DIR = BASE_DIR / "data"
LOG_STATE_FILE = DATA_DIR / "file_state.json"
VECTOR_DB_PATH = DATA_DIR / "faiss.index"

DEFAULT_TARGET_LOG_DIR = "/var/log/LMS_LOG/"
DEFAULT_ANALYSIS_OUTPUT_FILE = "/var/log/analyzer_results.json"
DEFAULT_OPERATIONAL_LOG_FILE = BASE_DIR / "analyzer_script.log"

LMS_TARGET_LOG_DIR = Path(os.getenv("LMS_TARGET_LOG_DIR", DEFAULT_TARGET_LOG_DIR))
LMS_ANALYSIS_OUTPUT_FILE = Path(os.getenv("LMS_ANALYSIS_OUTPUT_FILE", DEFAULT_ANALYSIS_OUTPUT_FILE))
LMS_OPERATIONAL_LOG_FILE = Path(os.getenv("LMS_OPERATIONAL_LOG_FILE", str(DEFAULT_OPERATIONAL_LOG_FILE)))

# 優化的參數設定
CACHE_SIZE = int(os.getenv("LMS_CACHE_SIZE", 50_000))  # 增大快取
SAMPLE_TOP_PERCENT = int(os.getenv("LMS_SAMPLE_TOP_PERCENT", 5))  # 降低取樣率
BATCH_SIZE = int(os.getenv("LMS_LLM_BATCH_SIZE", 5))  # 降低批次大小
MAX_LINES_PER_RUN = int(os.getenv("LMS_MAX_LINES_PER_RUN", 100))  # 限制單次處理量
MAX_EXECUTION_TIME = int(os.getenv("LMS_MAX_EXECUTION_TIME", 50))  # 最大執行時間（秒）
MAX_HOURLY_COST_USD = float(os.getenv("LMS_MAX_HOURLY_COST_USD", 2.0))  # 降低成本限制
PRICE_IN_PER_1K_TOKENS = float(os.getenv("LMS_PRICE_IN_PER_1K_TOKENS", 0.000125))
PRICE_OUT_PER_1K_TOKENS = float(os.getenv("LMS_PRICE_OUT_PER_1K_TOKENS", 0.000375))

# 優化的向量搜尋閾值
SIM_T_ATTACK_L2_THRESHOLD = float(os.getenv("LMS_SIM_T_ATTACK_L2_THRESHOLD", 0.25))  # 更嚴格
SIM_N_NORMAL_L2_THRESHOLD = float(os.getenv("LMS_SIM_N_NORMAL_L2_THRESHOLD", 0.15))  # 更嚴格
NOVELTY_L2_THRESHOLD = float(os.getenv("LMS_NOVELTY_L2_THRESHOLD", 0.4))  # 更嚴格

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_ENABLED = bool(GEMINI_API_KEY and ChatGoogleGenerativeAI)
LLM_MODEL_NAME = os.getenv("LMS_LLM_MODEL_NAME", "gemini-1.5-flash-latest")

DATA_DIR.mkdir(parents=True, exist_ok=True)
if LMS_ANALYSIS_OUTPUT_FILE.parent != Path("/var/log"):
    LMS_ANALYSIS_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
if LMS_OPERATIONAL_LOG_FILE.parent != Path("/var/log"):
    LMS_OPERATIONAL_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# ────────────────────────────
# 超時控制
# ────────────────────────────
class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("執行超時")

signal.signal(signal.SIGALRM, timeout_handler)

# ────────────────────────────
# 日誌記錄設定（簡化）
# ────────────────────────────
logging.basicConfig(
    level=logging.WARNING,  # 降低日誌級別
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ────────────────────────────
# 優化的 Embedding 工具
# ────────────────────────────
def init_embedding_model():
    """延遲初始化模型"""
    global SENTENCE_MODEL, EMBED_DIM
    if SENTENCE_MODEL is None:
        try:
            logger.info("正在載入 Sentence Transformer 模型...")
            SENTENCE_MODEL = SentenceTransformer(EMBEDDING_MODEL_NAME)
            EMBED_DIM = SENTENCE_MODEL.get_sentence_embedding_dimension()
            logger.info(f"模型載入完成，維度: {EMBED_DIM}")
        except Exception as e:
            logger.error(f"模型載入失敗: {e}")
            SENTENCE_MODEL = None

def embed(text: str) -> List[float]:
    if SENTENCE_MODEL is None:
        init_embedding_model()
    
    if SENTENCE_MODEL:
        try:
            embedding_vector = SENTENCE_MODEL.encode(text, convert_to_numpy=True)
            return embedding_vector.tolist()
        except Exception as e:
            logger.error(f"Embedding 生成失敗: {e}")
    
    # 回退到 SHA256 偽向量
    digest = hashlib.sha256(text.encode('utf-8', 'replace')).digest()
    vec_template = list(digest)
    vec = []
    while len(vec) < EMBED_DIM:
        vec.extend(vec_template)
    return [v / 255.0 for v in vec[:EMBED_DIM]]

# ────────────────────────────
# 優化的 FAISS 向量索引
# ────────────────────────────
class VectorIndex:
    def __init__(self, path: Path, dimension: int):
        self.path = path
        self.dimension = dimension
        self.index: Optional[faiss.Index] = None
        self._initialized = False

    def _lazy_load(self):
        """延遲載入索引"""
        if self._initialized or faiss is None:
            return
        
        if self.path.exists():
            try:
                self.index = faiss.read_index(str(self.path))
                logger.info(f"載入 FAISS 索引: {self.index.ntotal} 個向量")
            except Exception as e:
                logger.error(f"讀取 FAISS 索引失敗: {e}")
                self.index = faiss.IndexFlatL2(self.dimension)
        else:
            self.index = faiss.IndexFlatL2(self.dimension)
        
        self._initialized = True

    def save(self):
        if faiss and self.index is not None:
            try:
                faiss.write_index(self.index, str(self.path))
            except Exception as e:
                logger.error(f"儲存 FAISS 索引失敗: {e}")

    def search(self, vec: List[float], k: int = 5) -> Tuple[List[int], List[float]]:
        import numpy as np
        self._lazy_load()
        if self.index is None or self.index.ntotal == 0:
            return [], []
        
        query_vector = np.array([vec], dtype=np.float32)
        dists, ids = self.index.search(query_vector, k)
        return ids[0].tolist(), dists[0].tolist()

    def add(self, vecs: List[List[float]]):
        import numpy as np
        self._lazy_load()
        if self.index is not None:
            vectors_to_add = np.array(vecs, dtype=np.float32)
            self.index.add(vectors_to_add)

VECTOR_DB = VectorIndex(VECTOR_DB_PATH, EMBED_DIM)

# ────────────────────────────
# LRU Cache（不變）
# ────────────────────────────
class LRUCache(OrderedDict):
    def __init__(self, capacity: int):
        super().__init__()
        self.capacity = capacity
    def get(self, key: Any) -> Optional[Any]:
        if key in self:
            self.move_to_end(key)
            return self[key]
        return None
    def put(self, key: Any, value: Any):
        if key in self:
            self.move_to_end(key)
        self[key] = value
        if len(self) > self.capacity:
            self.popitem(last=False)

CACHE = LRUCache(CACHE_SIZE)

# ────────────────────────────
# 優化的 Gemini LLM 設定
# ────────────────────────────
LLM_CHAIN: Optional[Runnable] = None
if GEMINI_ENABLED and ChatGoogleGenerativeAI and PromptTemplate:
    try:
        llm = ChatGoogleGenerativeAI(
            model=LLM_MODEL_NAME,
            google_api_key=GEMINI_API_KEY,
            temperature=0.2,  # 降低溫度
            timeout=20,  # 設定超時
            convert_system_message_to_human=True,
        )
        
        # 簡化的 Prompt
        PROMPT_TEMPLATE_STR = """分析以下日誌是否為攻擊行為。回應JSON格式:
{"is_attack": boolean, "attack_type": "類型", "severity": "High/Medium/Low/None"}

日誌: {log_entry}
JSON:"""
        
        PROMPT = PromptTemplate(
            input_variables=["log_entry"],
            template=PROMPT_TEMPLATE_STR
        )
        LLM_CHAIN = PROMPT | llm
        logger.info(f"LLM 初始化完成")
    except Exception as e:
        logger.error(f"LLM 初始化失敗: {e}")
        GEMINI_ENABLED = False
        LLM_CHAIN = None

# ────────────────────────────
# 檔案狀態管理（簡化）
# ────────────────────────────
def load_state() -> Dict[str, Dict[str, Any]]:
    if LOG_STATE_FILE.exists():
        try:
            return json.loads(LOG_STATE_FILE.read_text(encoding='utf-8'))
        except Exception:
            return {}
    return {}

def save_state(state: Dict[str, Dict[str, Any]]):
    try:
        LOG_STATE_FILE.write_text(json.dumps(state, indent=2), encoding='utf-8')
    except Exception as e:
        logger.error(f"儲存狀態失敗: {e}")

STATE = load_state()

# ────────────────────────────
# 優化的工具函式
# ────────────────────────────
def open_log(path: Path) -> io.BufferedReader:
    if path.suffix == ".gz": return gzip.open(path, "rb")
    if path.suffix == ".bz2": return bz2.open(path, "rb")
    return path.open("rb")

def tail_since(path: Path, max_lines: int = MAX_LINES_PER_RUN) -> List[str]:
    """優化的日誌讀取，限制行數"""
    try: 
        inode = path.stat().st_ino
    except FileNotFoundError: 
        return []
    
    file_key = str(path.resolve())
    stored = STATE.get(file_key, {"inode": inode, "offset": 0})
    
    if stored["inode"] != inode:
        stored = {"inode": inode, "offset": 0}
    
    new_lines: List[str] = []
    try:
        with open_log(path) as f:
            f.seek(stored["offset"])
            for line_bytes in f:
                if len(new_lines) >= max_lines:  # 限制讀取行數
                    break
                try: 
                    new_lines.append(line_bytes.decode("utf-8").rstrip())
                except UnicodeDecodeError:
                    new_lines.append(line_bytes.decode("utf-8", "replace").rstrip())
            stored["offset"] = f.tell()
    except Exception as e:
        logger.error(f"讀取日誌失敗: {e}")
        return []
    
    STATE[file_key] = stored
    return new_lines

def parse_status(line: str) -> int:
    """從標準的 Apache/Nginx 日誌格式中提取 HTTP 狀態碼"""
    match = re.search(r'"[^"]*"\s+(\d{3})\b', line)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            pass
    return 0

def response_time(line: str) -> float:
    """從包含 resp_time:數字 格式的行中提取響應時間"""
    match = re.search(r'resp_time:(\d+(?:\.\d+)?)', line)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            pass
    return 0.0

# ────────────────────────────
# 優化的快速評分
# ────────────────────────────
SUSPICIOUS_KEYWORDS = ["/etc/passwd", "<script>", " OR ", "SELECT ", "UNION ", "../"]

def fast_score(line: str) -> float:
    """優化的快速評分函式"""
    score = 0.0
    line_lower = line.lower()
    
    # HTTP 狀態碼檢查
    try:
        status = int(line.split("\"")[2].strip().split()[0])
        if status >= 400: score += 0.5
    except (ValueError, IndexError): pass
    
    # 關鍵字檢查（優化）
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in line_lower:
            score += 0.2
            break  # 找到一個就跳出
    
    # User-Agent 檢查
    if any(ua in line_lower for ua in ["nmap", "sqlmap", "curl/"]):
        score += 0.3
    
    return min(score, 1.0)

# ────────────────────────────
# 優化的 LLM 成本追蹤
# ────────────────────────────
class LLMCostTracker:
    def __init__(self):
        self.cost_hourly = 0.0
        self.total_cost = 0.0
        self._window_start_time = datetime.now(timezone.utc)
    
    def add_usage(self, in_tok: int, out_tok: int):
        cost = (in_tok / 1000 * PRICE_IN_PER_1K_TOKENS) + (out_tok / 1000 * PRICE_OUT_PER_1K_TOKENS)
        self.cost_hourly += cost
        self.total_cost += cost
    
    def reset_if_window_passed(self):
        if datetime.now(timezone.utc) - self._window_start_time > timedelta(hours=1):
            self.cost_hourly = 0.0
            self._window_start_time = datetime.now(timezone.utc)
    
    def get_hourly_cost(self) -> float: 
        return self.cost_hourly

COST_TRACKER = LLMCostTracker()

def llm_analyse_with_timeout(lines: List[str], timeout: int = 15) -> List[Optional[dict]]:
    """帶超時的 LLM 分析"""
    if not LLM_CHAIN: 
        return [None] * len(lines)
    
    results: List[Optional[dict]] = [None] * len(lines)
    
    # 檢查快取
    uncached_lines = []
    uncached_indices = []
    for idx, line in enumerate(lines):
        if (cached := CACHE.get(line)) is not None:
            results[idx] = cached
        else:
            uncached_lines.append(line)
            uncached_indices.append(idx)
    
    if not uncached_lines:
        return results
    
    # 成本檢查
    COST_TRACKER.reset_if_window_passed()
    if COST_TRACKER.get_hourly_cost() >= MAX_HOURLY_COST_USD:
        logger.warning(f"達到成本上限 ${MAX_HOURLY_COST_USD}")
        for i in uncached_indices:
            results[i] = {"is_attack": False, "attack_type": "N/A", "severity": "None"}
        return results
    
    # 使用 ThreadPoolExecutor 進行並行處理
    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            batch_inputs = [{"log_entry": line} for line in uncached_lines]
            future_to_idx = {
                executor.submit(LLM_CHAIN.invoke, inp): i 
                for i, inp in enumerate(batch_inputs)
            }
            
            for future in as_completed(future_to_idx, timeout=timeout):
                idx = future_to_idx[future]
                orig_idx = uncached_indices[idx]
                line = uncached_lines[idx]
                
                try:
                    response = future.result()
                    content = getattr(response, 'content', str(response))
                    analysis = json.loads(content)
                    results[orig_idx] = analysis
                    CACHE.put(line, analysis)
                except Exception as e:
                    error_result = {"is_attack": True, "attack_type": "LLM Error", "severity": "Medium"}
                    results[orig_idx] = error_result
                    CACHE.put(line, error_result)
    
    except TimeoutError:
        logger.warning(f"LLM 分析超時 ({timeout}s)")
        for i in uncached_indices:
            if results[i] is None:
                results[i] = {"is_attack": False, "attack_type": "Timeout", "severity": "None"}
    
    return results

# ────────────────────────────
# 優化的主處理流程
# ────────────────────────────
def process_logs_optimized(log_paths: List[Path]) -> List[Dict[str, Any]]:
    """優化的主處理函式"""
    
    # 1. 快速收集新日誌（限制數量）
    all_new_lines = []
    for path in log_paths:
        if path.is_file():
            lines = tail_since(path, MAX_LINES_PER_RUN // len(log_paths))
            all_new_lines.extend(lines)
            if len(all_new_lines) >= MAX_LINES_PER_RUN:
                break
    
    if not all_new_lines:
        logger.info("無新日誌")
        save_state(STATE)
        return []
    
    # 2. 快速評分和取樣
    scored_lines = [(fast_score(line), line) for line in all_new_lines]
    scored_lines.sort(key=lambda x: x[0], reverse=True)
    
    # 只取高分的日誌
    high_score_lines = [(s, l) for s, l in scored_lines if s > 0.1]
    num_to_sample = min(len(high_score_lines), max(1, int(len(all_new_lines) * SAMPLE_TOP_PERCENT / 100)))
    top_lines = high_score_lines[:num_to_sample]
    
    if not top_lines:
        logger.info("無高分日誌需要分析")
        save_state(STATE)
        return []
    
    logger.info(f"選出 {len(top_lines)} 行日誌進行分析")
    
    # 3. 向量過濾（簡化）
    logs_for_llm = []
    vector_filtered = {}
    
    for score, line in top_lines:
        if len(logs_for_llm) >= BATCH_SIZE * 2:  # 限制 LLM 處理量
            break
            
        # 簡化的向量過濾邏輯
        if VECTOR_DB.index is not None:
            try:
                vec = embed(line)
                ids, dists = VECTOR_DB.search(vec, k=1)
                min_dist = dists[0] if dists else float('inf')
                
                if min_dist < SIM_N_NORMAL_L2_THRESHOLD:
                    vector_filtered[line] = {
                        "is_attack": False, 
                        "attack_type": "N/A", 
                        "severity": "None",
                        "source": "VectorFilter"
                    }
                    continue
            except Exception as e:
                logger.error(f"向量處理失敗: {e}")
        
        logs_for_llm.append(line)
    
    # 4. LLM 分析（帶超時）
    llm_results = {}
    if logs_for_llm and GEMINI_ENABLED:
        logger.info(f"送交 LLM 分析 {len(logs_for_llm)} 筆日誌")
        analyses = llm_analyse_with_timeout(logs_for_llm, timeout=15)
        for line, analysis in zip(logs_for_llm, analyses):
            if analysis:
                analysis["source"] = "LLM"
                llm_results[line] = analysis
    
    # 5. 結果彙整
    exported_results = []
    alerts = 0
    
    for score, line in top_lines:
        analysis = llm_results.get(line, vector_filtered.get(line))
        
        exported_results.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "original_log": line,
            "fast_score": round(score, 2),
            "analysis": analysis
        })
        
        if analysis and analysis.get("is_attack"):
            alerts += 1
    
    logger.warning(f"發現 {alerts} 個潜在攻擊")
    save_state(STATE)
    VECTOR_DB.save()

    return exported_results

def process_logs(log_paths: List[Path]) -> List[Dict[str, Any]]:
    """接受文件路徑列表並返回處理結果"""
    return process_logs_optimized(log_paths)

# ────────────────────────────
# 主執行入口
# ────────────────────────────
if __name__ == "__main__":
    # 設定執行超時
    signal.alarm(MAX_EXECUTION_TIME)
    
    try:
        logger.info(f"優化版日誌分析器啟動 (超時: {MAX_EXECUTION_TIME}s)")
        
        if not LMS_TARGET_LOG_DIR.is_dir():
            logger.error(f"日誌目錄不存在: {LMS_TARGET_LOG_DIR}")
            sys.exit(1)
        
        log_files = [
            p for p in LMS_TARGET_LOG_DIR.iterdir() 
            if p.is_file() and p.suffix.lower() in [".log", ".gz", ".bz2"]
        ]
        
        if not log_files:
            logger.warning("未找到日誌檔案")
            sys.exit(0)
        
        # 只處理最新的幾個檔案
        log_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        log_files = log_files[:5]  # 只處理最新的5個檔案
        
        logger.info(f"處理檔案: {[p.name for p in log_files]}")
        
        results = process_logs_optimized(log_files)
        
        if results:
            try:
                LMS_ANALYSIS_OUTPUT_FILE.write_text(
                    json.dumps(results, ensure_ascii=False, indent=2), 
                    encoding="utf-8"
                )
                logger.info(f"結果已輸出: {len(results)} 筆記錄")
            except Exception as e:
                logger.error(f"輸出結果失敗: {e}")
        
        logger.info(f"總成本: ${COST_TRACKER.total_cost:.4f}")
        
    except TimeoutException:
        logger.error(f"執行超時 ({MAX_EXECUTION_TIME}s)")
        sys.exit(1)
    except Exception as e:
        logger.error(f"執行錯誤: {e}")
        sys.exit(1)
    finally:
        signal.alarm(0)  # 取消超時
        logger.info("分析器執行完畢")
