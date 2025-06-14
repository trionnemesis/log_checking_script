# MS AI 日誌分析與告警系統 (基於 Gemini 與 LangChain)

## 概覽與介紹

本系統旨在自動化分析 `/var/log/LMS_LOG/` 目錄下的日誌檔案，利用啟發式規則、向量搜尋（模擬）以及 Google Gemini 大型語言模型（透過 LangChain 框架）來識別潛在的攻擊或異常行為，並在偵測到可疑活動時產生告警。

**核心技術：**

- **Python:** 主要程式語言。
- **LangChain:** 用於簡化與大型語言模型 (LLM) 的互動。
- **Google Gemini Pro (透過 API):** 用於對可疑日誌進行深度分析。腳本中使用 `gemini-2.0-flash` 作為模型範例。

---

## I. 系統架構 (概念流程)

1. **週期性執行:** 透過 cron job (或其他排程方式) 每小時觸發一次腳本。
2. **日誌讀取與選擇:**
    - 掃描指定的日誌目錄 (例如 `/var/log/LMS_LOG/`)。
    - 找到其中最新修改的 `.log` 檔案作為當前處理目標。
    - 若無 `.log` 檔案，則會嘗試在該目錄下產生一個模擬日誌檔 (`simulated_lms_activity.log`) 供測試。
    - 使用時間戳檔案 (`/tmp/lms_last_run_log_timestamp.txt`) 記錄上次處理到的日誌行時間，以實現增量處理。
3. **初步過濾:**
    - **解析器 (Parser):** 解析每一行日誌。
    - **啟發式規則 (Heuristics):** 根據預設規則 (如非 2xx/3xx 狀態碼、過長的回應時間、可疑關鍵字等) 快速篩選。
    - 僅抽取得分最高約 10% 的日誌進入後續分析，以控制成本。
4. **向量搜尋 (模擬):**
    - 通過啟發式規則的日誌，會進行模擬的攻擊向量和正常向量比對。
    - **Attack-vec search:** 若與攻擊向量相似度高於閾值，標記為可疑。
    - **Normal-vec search:** 若與正常向量相似度低於閾值，也標記為可疑。
    - 若兩者皆未命中，則丟棄。
5. **向量過濾與事件聚合:**
    - 基於向量距離判斷日誌是否與已知模式相符，新穎或高相似者才會送交 LLM。
    - 搜尋最近鄰並將相同鄰居的日誌歸為同一群組，只挑選代表樣本分析。
6. **LLM 深度分析 (Gemini via LangChain):**
    - 將每個分組的代表日誌透過 LangChain 提交給 Gemini 模型。
    - Gemini 回傳 JSON 格式的分析結果，並套用到同組內的其他日誌。
7. **結果記錄與通知:**
    - **AI 告警日誌:** Gemini 的分析結果、Token 消耗、費用等資訊記錄到 `/tmp/LMS_AI_ALERTS/LMS_AI_ALERT_YYYYMMDD.log`。
    - **Token 使用日誌:** API Token 使用量記錄到 `/tmp/LMS_TOKEN_USAGE/LMS_TOKEN_USAGE.log`。
    - **成本控制:** 若 API 累計費用超過設定上限 (預設 5 USD)，則停止呼叫 Gemini 並記錄。
    - **郵件通知 (模擬):** 對於偵測到的告警或費用超限情況，模擬發送郵件。

---

## II. 建議安裝環境

- **作業系統 (Operating System):**
    - 建議使用 Linux 發行版 (如 Ubuntu, CentOS, Debian)。因為腳本設計用來讀取類 Unix 系統常見的日誌路徑 (如 `/var/log/`)。
    - macOS 應該也可以運作。
    - Windows 可能需要調整路徑寫法及排程方式。
- **Python 版本:**
    - Python 3.8 或更高版本。
- **虛擬環境 (Virtual Environment - 強烈建議):**
    - 使用 `venv` 或 `conda` 建立獨立的 Python 環境，以避免套件版本衝突。
    - 例如：`python3 -m venv lms_ai_env`
- **其他:monitor_resources.sh 為替代腳本可以設定到crontab:**
    - monitor_resources.sh （含狀態檔與冷卻機制，避免重複呼叫 API）
---

## III. 安裝步驟與說明

1. **先決條件 (Prerequisites):**
    - **Python 與 Pip:** 確保您的系統已安裝 Python 3.8+ 及 Pip。
        
        ```bash
        python3 --version
        pip3 --version
        
        ```
        
    - **日誌目錄存取權限:** 執行腳本的使用者需要有權限讀取您設定的 `LOG_DIRECTORY` (預設為 `/var/log/LMS_LOG/`) 及其中的檔案。如果腳本需要在該目錄下創建模擬日誌檔 (當目錄為空時)，則還需要寫入權限。
    - **Google AI Studio API Key:**
        - 您需要前往 [Google AI Studio](https://aistudio.google.com/) 取得 Gemini API 金鑰。
        - 此金鑰將用於讓腳本透過 LangChain 與 Gemini 模型進行通訊。
2. **設定虛擬環境 (建議):**
    - 開啟終端機，進入您想放置專案的目錄。
    - 建立虛擬環境 (假設名稱為 `lms_ai_env`):
        
        ```bash
        python3 -m venv lms_ai_env
        
        ```
        
    - 啟動虛擬環境:
    
    啟動後，您的終端機提示符前應會出現 `(lms_ai_env)`。
        - Linux/macOS:
            
            ```bash
            source lms_ai_env/bin/activate
            
            ```
            
        - Windows:
            
            ```bash
            lms_ai_env\\Scripts\\activate
            
            ```
            
3. **安裝 Python 套件:**
    - 在已啟動的虛擬環境中，執行以下指令安裝必要的 Python 函式庫：
        
        ```bash
        pip install langchain langchain-google-genai google-api-python-client
        
        ```
        
    - **套件說明:**
        - `langchain`: LangChain 核心函式庫，提供與 LLM 互動的框架。
        - `langchain-google-genai`: LangChain 專用於整合 Google Generative AI (包括 Gemini 模型) 的套件。
        - `google-api-python-client`: Google API 的 Python 客戶端函式庫，`langchain-google-genai` 可能會依賴它。
4. **取得並設定腳本:**
    - 將提供的 Python 腳本儲存為一個 `.py` 檔案 (例如：`lms_log_analyzer.py`)。
    - **設定 API 金鑰:**
        - **建議方式 (環境變數):** 在您的終端機設定環境變數 `GEMINI_API_KEY`。
        (若要永久生效，請將此行加入您的 shell 設定檔，如 `.bashrc`, `.zshrc` 等)
            
            ```bash
            export GEMINI_API_KEY="YOUR_API_KEY_HERE"
            
            ```
            
        - **腳本內提示輸入:** 如果未設定環境變數，腳本在執行時會提示您輸入 API 金鑰。
        - **直接寫入腳本 (不建議用於生產環境):** 您也可以直接在腳本中修改 `GEMINI_API_KEY = "YOUR_API_KEY_HERE"`，但請注意安全風險。
    - **檢查並調整腳本內的「配置設定 (Configurable Settings)」部分:**
        
        ```python
        # --- 配置設定 (Configurable Settings) ---
        SIM_T_ATTACK_THRESHOLD = 0.8
        SIM_N_NORMAL_THRESHOLD = 0.6
        GEMINI_API_CALL_ENABLED = True
        GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") # 金鑰設定點
        
        MAX_HOURLY_COST_USD = 5.0
        LOG_DIRECTORY = "/var/log/LMS_LOG/" # 主要日誌目錄
        MOCK_LOG_FILENAME_IN_DIR = "simulated_lms_activity.log" # 若目錄為空，產生的模擬檔名
        
        AI_ALERT_LOG_DIR = "/tmp/LMS_AI_ALERTS/" # AI 告警日誌存放目錄
        TOKEN_USAGE_LOG_DIR = "/tmp/LMS_TOKEN_USAGE/" # Token 使用量日誌存放目錄
        LAST_RUN_TIMESTAMP_FILE = "/tmp/lms_last_run_log_timestamp.txt" # 上次執行時間戳檔案
        # ... 其他設定 ...
        
        ```
        
        - 確認 `LOG_DIRECTORY` 指向您正確的日誌來源目錄。
        - `AI_ALERT_LOG_DIR`, `TOKEN_USAGE_LOG_DIR`, `LAST_RUN_TIMESTAMP_FILE` 預設使用 `/tmp/` 路徑，通常有較好的權限相容性。若需更改，請確保執行腳本的使用者對新路徑有寫入權限。
5. **目錄與檔案權限 (Directory & File Permissions):**
    - **讀取日誌:** 執行腳本的使用者必須擁有對 `LOG_DIRECTORY` 及其內部日誌檔案的**讀取**權限。
        
        ```bash
        # 範例：檢查目錄權限
        ls -ld /var/log/LMS_LOG/
        # 範例：檢查檔案權限 (假設有個 access.log)
        ls -l /var/log/LMS_LOG/access.log
        
        ```
        
    - **寫入輸出檔案:** 執行腳本的使用者必須擁有對 `AI_ALERT_LOG_DIR`, `TOKEN_USAGE_LOG_DIR` 以及 `LAST_RUN_TIMESTAMP_FILE` 所在目錄的**寫入**權限，以便腳本可以建立和寫入這些日誌/狀態檔案。
        - 如果這些目錄 (如 `/tmp/LMS_AI_ALERTS/`) 不存在，腳本會嘗試創建它們。
    - **模擬日誌產生:** 如果 `LOG_DIRECTORY` 中沒有 `.log` 檔案，腳本會嘗試在 `LOG_DIRECTORY` 中創建 `MOCK_LOG_FILENAME_IN_DIR`。這種情況下，執行腳本的使用者也需要對 `LOG_DIRECTORY` 的**寫入**權限。

---

## IV. 執行腳本

1. **啟動虛擬環境** (如果尚未啟動):
    
    ```bash
    source lms_ai_env/bin/activate
    
    ```
    
2. **執行腳本:**
(將 `lms_log_analyzer.py` 替換為您儲存腳本的實際檔名)
    
    ```bash
    python lms_log_analyzer.py
    
    ```
    
3. **腳本運作流程簡述:**
    - 腳本啟動，讀取設定。
    - 掃描 `LOG_DIRECTORY`，選取最新的 `.log` 檔案 (或產生模擬檔案)。
    - 讀取 `LAST_RUN_TIMESTAMP_FILE` 中的時間戳。
    - 從選定的日誌檔案中讀取並處理在該時間戳之後的新增日誌行。
    - 進行啟發式過濾和模擬的向量搜尋。
    - 將可疑日誌提交給 Gemini 分析。
    - 記錄分析結果、Token 用量。
    - 模擬發送告警郵件。
    - 更新 `LAST_RUN_TIMESTAMP_FILE` 中的時間戳。
4. **預期輸出檔案位置 (預設):**
    - AI 告警: `/tmp/LMS_AI_ALERTS/LMS_AI_ALERT_YYYYMMDD.log`
    - Token 用量: `/tmp/LMS_TOKEN_USAGE/LMS_TOKEN_USAGE.log`
    - 下次執行時間戳: `/tmp/lms_last_run_log_timestamp.txt`

---

## V. 腳本設定詳解 (Configurable Settings)

在 Python 腳本的開頭，「配置設定」區域包含以下重要變數，您可以根據需求調整：

- `SIM_T_ATTACK_THRESHOLD = 0.8`: 攻擊向量搜尋的相似度閾值，高於此值視為潛在攻擊。
- `SIM_N_NORMAL_THRESHOLD = 0.6`: 正常向量搜尋的相似度閾值，*低於*此值視為行為異常。
- `GEMINI_API_CALL_ENABLED = True`: 是否真的呼叫 Gemini API。設為 `False` 可在不產生費用的情況下測試腳本的其他部分邏輯 (API 呼叫會被模擬)。
- `GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")`: Gemini API 金鑰。優先從環境變數讀取。
- `MAX_HOURLY_COST_USD = 5.0`: 每小時 Gemini API 呼叫的費用上限 (美元)。達到此上限後，腳本將在本小時內停止呼叫 API。
- `LOG_DIRECTORY = "/var/log/LMS_LOG/"`: 指定存放原始日誌檔案的目錄。腳本會掃描此目錄下的 `.log` 檔案。
- `MOCK_LOG_FILENAME_IN_DIR = "simulated_lms_activity.log"`: 如果 `LOG_DIRECTORY` 中沒有找到任何 `.log` 檔案，腳本會嘗試在此目錄下創建以此命名的模擬日誌檔案。
- `AI_ALERT_LOG_DIR = "/tmp/LMS_AI_ALERTS/"`: 存放 AI 分析告警結果的目錄。
- `TOKEN_USAGE_LOG_DIR = "/tmp/LMS_TOKEN_USAGE/"`: 存放 API Token 使用量記錄的目錄。
- `LAST_RUN_TIMESTAMP_FILE = "/tmp/lms_last_run_log_timestamp.txt"`: 記錄上次成功處理的日誌行時間戳的檔案路徑，用於增量處理。
- `PRICE_PER_1000_TOKENS_INPUT` 和 `PRICE_PER_1000_TOKENS_OUTPUT`: 用於估算 Gemini API 費用的單價 (美元/千 Token)。**請參考最新的 Google Cloud 定價進行調整。**

---

## VI. 未來可改進建議

1. **增強型日誌解析 (Enhanced Log Parsing):**
    - 對於更複雜或多樣的日誌格式，可以考慮使用更強大的日誌解析函式庫，如 `python-grok`。
2. **真實向量搜尋與嵌入 (Advanced Vector Search):**
    - 整合真正的向量資料庫 (如 FAISS, Milvus, Pinecone, Qdrant 等)。
    - 使用文本嵌入模型 (如 Google 的 `text-embedding-004` 模型，或開源的 Sentence Transformers) 將日誌條目轉換為向量，以實現更精確的攻擊模式和正常模式比對。
3. **支援壓縮日誌處理 (Compressed Log Handling):**
    - 增加讀取和即時解壓縮已壓縮日誌檔案 (如 `.gz`, `.bz2`) 的功能，以便分析歷史歸檔日誌。
4. **更完善的多檔案與輪替日誌狀態管理 (State Management):**
    - 如果需要同時處理目錄中多個檔案或更精確地追蹤已處理的日誌段落（而不僅是依賴最新檔案和內部時間戳），可以考慮更複雜的狀態管理機制，例如記錄每個檔案的處理位元組偏移 (byte offset) 或 inode。
5. **錯誤處理與健壯性 (Error Handling & Resilience):**
    - 增強腳本的錯誤處理能力，例如增加 API 呼叫的重試機制。
    - 對於無法預期的日誌格式或系統問題，提供更友好的錯誤回饋和恢復能力。
6. **外部化設定管理 (Configuration Management):**
    - 將所有可配置參數（如 API 金鑰、路徑、閾值等）移至外部設定檔 (如 YAML, JSON, `.env` 檔案)，而不是直接寫在腳本中，方便管理和部署。
7. **近即時處理 (Near Real-time Processing):**
    - 若需更頻繁的分析，可以調整 cron job 的執行頻率。
    - 考慮與日誌收集/串流解決方案 (如 Filebeat, Fluentd, Kafka) 整合，以實現更接近即時的日誌分析。
8. **進階告警整合 (Advanced Alerting):**
    - 除了模擬郵件，可以整合更專業的告警平台，如 PagerDuty, Slack, Opsgenie, Microsoft Teams 等，以便告警能更有效地觸達相關人員。
9. **安全性強化 (Security Enhancements):**
    - 對於生產環境，API 金鑰應使用更安全的儲存方式，如 HashiCorp Vault, Google Cloud Secret Manager, AWS Secrets Manager 等，而不是僅依賴環境變數或腳本內提示。
10. **LLM 成本優化 (Cost Optimization for LLM):**
    - 實現更精細的成本追蹤。
    - 開發可疑日誌的自適應取樣策略 (例如，只將最可疑的 N% 日誌送往 LLM)。
    - 為相似的查詢實作快取機制，避免重複呼叫 LLM。
11. **LLM 批次處理 (Batch Processing for LLM):**
    - 如果一次發現大量可疑日誌，研究 Gemini API 是否支援或能從批次請求中受益，以減少 API 呼叫的總體開銷。
12. **Web UI/儀表板 (Web UI/Dashboard):**
    - 開發一個簡單的 Web 介面，用於查看告警、統計數據、Token 使用情況，甚至管理部分設定。
13. **單元測試與整合測試 (Unit & Integration Testing):**
    - 為腳本的關鍵部分編寫單元測試和整合測試，以確保程式碼的品質、可靠性，並在未來修改時能快速發現潛在問題。
14. **日誌輪替感知 (Log Rotation Awareness):**
    - 雖然目前選擇最新 `.log` 檔案的方式能應對部分輪替，但可以設計更明確的邏輯來識別和處理日誌輪替事件，確保數據的連續性。

---

## VII. 常見問題排解 (Troubleshooting Common Issues)

- **`ModuleNotFoundError: No module named 'some_package'`**
    - **原因:** Python 環境中缺少必要的套件。
    - **解決:** 啟動正確的虛擬環境，然後使用 `pip install some_package` 安裝。
- **權限錯誤 (Permission Denied / Errno 13)**
    - **原因:** 腳本執行使用者沒有讀取日誌目錄/檔案或寫入輸出目錄/檔案的權限。
    - **解決:**
        - 檢查並修正相關目錄和檔案的權限 (`ls -l`, `chmod`, `chown`)。
        - 確保以擁有正確權限的使用者執行腳本。
        - 將輸出路徑 (如 `AI_ALERT_LOG_DIR`, `LAST_RUN_TIMESTAMP_FILE`) 設定到使用者有權限寫入的位置 (如 `/tmp/` 或使用者家目錄下的子目錄)。
- **`[Errno 21] Is a directory`**
    - **原因:** 腳本試圖將一個目錄當作檔案來開啟。通常是因為 `LOG_DIRECTORY` 被錯誤地當作完整檔案路徑傳遞給了 `open()` 函數。
    - **解決:** 確保腳本中的路徑變數 (尤其是傳給 `open()` 的) 指向的是檔案而不是目錄。在此腳本的最新版本中，應檢查 `get_latest_log_file` 是否正確返回檔案路徑。
- **API 金鑰問題 (認證失敗、401/403 錯誤)**
    - **原因:** `GEMINI_API_KEY` 未設定、設定錯誤或金鑰本身無效/權限不足。
    - **解決:**
        - 確認 `GEMINI_API_KEY` 已正確設定 (透過環境變數或腳本內提示)。
        - 驗證 API 金鑰是否有效，以及是否已為您的專案啟用 Gemini API。
        - 或者是使用openai key也可以但腳本需要對應的修改
        
- **日誌時間戳解析錯誤**
    - **原因:** 日誌檔案中的時間戳格式與腳本中 `read_incremental_logs` 函數預期的 `strptime` 格式不符。
    - **解決:** 修改 `read_incremental_logs` 中 `datetime.datetime.strptime(timestamp_str, "...")` 的格式字串，使其與您的實際日誌時間戳格式匹配。

---
```
架構圖
┌────────────┐
│ Log Source │   ← 來自 LMS 系統的 .log/.gz/.bz2 檔案
└────┬───────┘
│
▼
┌────────────┐
│  Parser    │ ← 逐行讀取新日誌、解壓縮、處理編碼
│ tail_since │
└────┬───────┘
│
▼
┌──────────────┐
│ Fast Scorer  │ ← 啟發式快速評分
│ fast_score() │
└────┬─────────┘
│top 10%
▼
┌────────────────────┐
│ Vector Embedder     │ ← 用 sentence-transformers 或 SHA256 偽向量
│ embed()             │
└────┬────────────────┘
│                ┌────────────────────┐
│                │ FAISS Vector Index │ ← 搜尋歷史相似模式
│───────────────▶│ search(), add()    │
└────────────────────┘
▼
┌────────────────────┐
│ Cluster Similar    │ ← 聚合相似事件
│ Logs               │
└────────┬───────────┘
         ▼
┌────────────────────┐
│ Gemini LLM (Langchain) │ ← 分析是否為攻擊行為
│ LLM_CHAIN.batch()      │
└────────┬──────────────┘
│
▼
┌────────────────────┐
│ Cache / Token Cost │ ← 避免重複分析 + 成本控制
│ LRUCache / Tracker │
└────────┬────────────┘
▼
┌────────────────────┐
│ Exporter            │ ← 將分析結果輸出為 JSON
│ JSON / Log Report   │
└────────────────────┘
```

## VIII. 自動化測試

專案內附帶 `test_analyzer.py`，使用 pytest 執行基本單元測試。

在專案根目錄下執行：

```bash
pytest
```

GitHub Actions 會在 Pull Request 時自動執行這些測試。
