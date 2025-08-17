# LMS 日誌分析與系統監控工具集

## 專案概覽

本專案提供一套完整的日誌分析與系統監控解決方案，包含三個核心執行腳本，利用 Google Gemini AI 進行智能分析，適用於安全監控、系統管理和異常檢測。

### 核心技術棧
- **Python 3.8+** - 主要程式語言
- **Google Gemini API** - AI 分析引擎
- **LangChain** - LLM 整合框架
- **FAISS** - 向量搜尋引擎
- **Sentence Transformers** - 文本嵌入模型
- **Shell Script** - 系統層面的自動化

---

## 系統架構與組件

### 三大核心腳本

#### 1. 🔍 `lms_log_analyzer_v2.py` - 智能日誌分析器
**主要功能：** 針對 LMS 系統日誌進行深度分析，識別潛在的安全威脅和攻擊行為

**技術特點：**
- 支援多種日誌格式（.log, .gz, .bz2）
- 基於向量搜尋的相似性分析
- LLM 驅動的攻擊行為識別
- 增量處理避免重複分析
- 成本控制與超時保護

#### 2. 📊 `log_analysis.sh` - 綜合日誌分析腳本
**主要功能：** 批次分析 HTTP 錯誤日誌和系統安全日誌，生成詳細的安全評估報告

**技術特點：**
- 平行處理提升分析效率
- 支援壓縮日誌檔案
- 自動生成時間戳報告
- Token 使用量統計
- 綜合安全評估摘要

#### 3. 🖥️ `monitor_resources.sh` - 系統資源監控器
**主要功能：** 即時監控系統資源使用狀況，在異常時提供 AI 驅動的診斷建議

**技術特點：**
- CPU、記憶體、磁碟、IO 監控
- 冷卻機制避免重複告警
- 智能服務重啟建議
- 狀態持久化管理

---

## 安裝與環境設定

### 系統需求
- **作業系統：** Linux (建議 Ubuntu 18.04+, CentOS 7+)
- **Python：** 3.8 或更高版本
- **記憶體：** 最少 2GB RAM
- **磁碟：** 最少 1GB 可用空間

### 依賴套件安裝

#### Python 套件
```bash
# 建立虛擬環境
python3 -m venv lms_env
source lms_env/bin/activate

# 安裝核心依賴
pip install langchain langchain-google-genai langchain-core
pip install sentence-transformers faiss-cpu
pip install google-generativeai

# 可選依賴（提升效能）
pip install numpy pandas
```

#### 系統工具
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install jq curl bc iostat

# CentOS/RHEL
sudo yum install jq curl bc sysstat
```

### API 金鑰設定

#### Google Gemini API
1. 前往 [Google AI Studio](https://aistudio.google.com/)
2. 取得 Gemini API 金鑰
3. 設定環境變數：
```bash
export GEMINI_API_KEY="your_api_key_here"
# 永久設定（加入 ~/.bashrc）
echo 'export GEMINI_API_KEY="your_api_key_here"' >> ~/.bashrc
```

---

## 使用指南

### 1. LMS 日誌分析器 (`lms_log_analyzer_v2.py`)

#### 基本用法
```bash
# 直接執行（使用預設設定）
python lms_log_analyzer_v2.py

# 使用環境變數自訂設定
export LMS_TARGET_LOG_DIR="/custom/log/path"
export LMS_MAX_LINES_PER_RUN=50
python lms_log_analyzer_v2.py
```

#### 重要環境變數
```bash
# 日誌來源目錄
export LMS_TARGET_LOG_DIR="/var/log/LMS_LOG"

# 分析結果輸出檔案
export LMS_ANALYSIS_OUTPUT_FILE="/var/log/analyzer_results.json"

# 單次處理行數限制
export LMS_MAX_LINES_PER_RUN=100

# 成本控制（美元/小時）
export LMS_MAX_HOURLY_COST_USD=2.0

# 向量搜尋閾值
export LMS_SIM_T_ATTACK_L2_THRESHOLD=0.25
export LMS_SIM_N_NORMAL_L2_THRESHOLD=0.15
```

#### 輸出格式
分析結果以 JSON 格式輸出：
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "original_log": "192.168.1.100 - - [15/Jan/2024:10:30:00] \"GET /admin\" 403",
  "fast_score": 0.7,
  "analysis": {
    "is_attack": true,
    "attack_type": "Directory Traversal",
    "severity": "Medium",
    "source": "LLM"
  }
}
```

### 2. 綜合日誌分析腳本 (`log_analysis.sh`)

#### 基本用法
```bash
# 使用預設設定執行
sudo ./log_analysis.sh

# 自訂設定執行
export LMS_TARGET_LOG_DIR="/custom/http/logs"
export MAX_LINES_TO_ANALYZE=30
./log_analysis.sh
```

#### 重要設定變數
```bash
# HTTP 日誌目錄
export LMS_TARGET_LOG_DIR="/var/log/LMS_LOG"

# 報告存放目錄
export REPORT_DIR="/var/log/report"

# 單次分析行數
export MAX_LINES_TO_ANALYZE=20

# 最大執行時間（秒）
export MAX_EXECUTION_TIME=600
```

#### 生成報告
腳本會在 `/var/log/report/` 目錄下生成時間戳報告：
```
security_report_20240115_103000.log
```

報告包含：
- HTTP 錯誤日誌分析
- 系統安全日誌分析
- 綜合安全評估摘要
- Token 使用量統計

### 3. 系統資源監控器 (`monitor_resources.sh`)

#### 基本用法
```bash
# 單次執行
sudo ./monitor_resources.sh

# 加入 crontab 定期執行（每5分鐘）
echo "*/5 * * * * /path/to/monitor_resources.sh" | sudo crontab -
```

#### 監控閾值設定
腳本內建閾值可在腳本頂部修改：
```bash
# CPU 使用率閾值
CPU_THRESHOLD=80

# 記憶體使用率閾值  
RAM_THRESHOLD=85

# IO 等待閾值
IO_WAIT_THRESHOLD=10

# 磁碟使用率閾值
DISK_THRESHOLD=85

# 冷卻時間（秒）
COOLDOWN_SECONDS=14400  # 4小時
```

#### 輸出與日誌
- **控制台輸出：** 即時監控狀態
- **日誌檔案：** `/var/log/server_monitor_gemini.log`
- **狀態檔案：** `/tmp/monitor_last_alert.state`

---

## 自動化部署

### Crontab 設定範例

```bash
# 編輯 crontab
sudo crontab -e

# 每小時執行日誌分析
0 * * * * cd /path/to/project && /path/to/lms_env/bin/python lms_log_analyzer_v2.py

# 每6小時執行綜合分析
0 */6 * * * cd /path/to/project && ./log_analysis.sh

# 每5分鐘監控系統資源
*/5 * * * * cd /path/to/project && ./monitor_resources.sh
```

### Systemd 服務設定

建立 `/etc/systemd/system/lms-monitor.service`：
```ini
[Unit]
Description=LMS Log Analyzer and Monitor
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/path/to/project
Environment=GEMINI_API_KEY=your_api_key
ExecStart=/path/to/lms_env/bin/python lms_log_analyzer_v2.py

[Install]
WantedBy=multi-user.target
```

啟用服務：
```bash
sudo systemctl daemon-reload
sudo systemctl enable lms-monitor.service
sudo systemctl start lms-monitor.service
```

---

## 效能優化與調校

### 記憶體優化
```bash
# 調整快取大小
export LMS_CACHE_SIZE=30000

# 降低批次處理大小
export LMS_LLM_BATCH_SIZE=3

# 限制單次處理量
export LMS_MAX_LINES_PER_RUN=50
```

### 成本控制
```bash
# 設定每小時成本上限
export LMS_MAX_HOURLY_COST_USD=1.0

# 調整取樣率
export LMS_SAMPLE_TOP_PERCENT=3

# 優化向量搜尋閾值
export LMS_SIM_T_ATTACK_L2_THRESHOLD=0.3
export LMS_SIM_N_NORMAL_L2_THRESHOLD=0.2
```

### 超時設定
```bash
# Python 腳本超時
export LMS_MAX_EXECUTION_TIME=30

# Shell 腳本超時
export MAX_EXECUTION_TIME=300
```

---

## 監控與告警

### 日誌檔案位置
```bash
# Python 分析器日誌
/path/to/project/analyzer_script.log

# Shell 分析腳本報告
/var/log/report/security_report_*.log

# 系統監控日誌
/var/log/server_monitor_gemini.log

# 分析結果
/var/log/analyzer_results.json
```

### 告警機制
1. **即時控制台輸出**
2. **結構化 JSON 結果**
3. **詳細分析報告**
4. **系統資源異常提醒**

---

## 故障排除

### 常見問題

#### 1. 權限錯誤
```bash
# 檢查日誌目錄權限
ls -la /var/log/LMS_LOG/

# 修正權限
sudo chmod -R 755 /var/log/LMS_LOG/
sudo chown -R $USER:$USER /var/log/report/
```

#### 2. API 金鑰問題
```bash
# 驗證環境變數
echo $GEMINI_API_KEY

# 測試 API 連接
curl -H "Authorization: Bearer $GEMINI_API_KEY" \
     https://generativelanguage.googleapis.com/v1beta/models
```

#### 3. 依賴套件問題
```bash
# 重新安裝套件
pip install --upgrade langchain langchain-google-genai
pip install --force-reinstall sentence-transformers
```

#### 4. 記憶體不足
```bash
# 監控記憶體使用
free -h
top -p $(pgrep -f lms_log_analyzer)

# 調整設定
export LMS_CACHE_SIZE=10000
export LMS_MAX_LINES_PER_RUN=20
```

### 除錯模式
```bash
# 啟用詳細日誌
export PYTHONPATH=/path/to/project
export LOG_LEVEL=DEBUG
python -u lms_log_analyzer_v2.py

# Shell 腳本除錯
bash -x log_analysis.sh
bash -x monitor_resources.sh
```

---

## 系統架構圖

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Log Sources   │    │   System Metrics │    │  External APIs  │
│                 │    │                  │    │                 │
│ • HTTP Logs     │    │ • CPU Usage      │    │ • Gemini API    │
│ • System Logs   │    │ • Memory Usage   │    │ • Token Counter │
│ • Security Logs │    │ • Disk I/O       │    │                 │
└─────┬───────────┘    └────────┬─────────┘    └─────────┬───────┘
      │                         │                        │
      ▼                         ▼                        │
┌─────────────────────────────────────────────────────────▼───────┐
│                    LMS Analysis Engine                          │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Log Parser   │  │ Fast Scorer  │  │ Vector Embedder      │  │
│  │ (Multi-fmt)  │  │ (Heuristic)  │  │ (Sentence Transform) │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                     │              │
│         ▼                 ▼                     ▼              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              FAISS Vector Index                         │   │
│  │          (Similarity Search & Clustering)               │   │
│  └─────────────────────┬───────────────────────────────────┘   │
│                        │                                       │
│                        ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           LangChain + Gemini LLM                        │   │
│  │        (Attack Detection & Classification)              │   │
│  └─────────────────────┬───────────────────────────────────┘   │
│                        │                                       │
│                        ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │         Cost Tracker & Cache Manager                    │   │
│  │           (Budget Control & Optimization)               │   │
│  └─────────────────────┬───────────────────────────────────┘   │
└────────────────────────┼─────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Output & Reporting                           │
│                                                                 │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐   │
│ │JSON Results │  │HTML Reports │  │ System Alerts           │   │
│ │(Structured) │  │(Detailed)   │  │ (Resource Monitoring)   │   │
│ └─────────────┘  └─────────────┘  └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 測試與驗證

### 單元測試
```bash
# 執行內建測試
python test_analyzer.py

# 使用 pytest
pip install pytest
pytest test_analyzer.py -v
```

### 整合測試
```bash
# 建立測試日誌
mkdir -p /tmp/test_logs
echo '192.168.1.100 - - [15/Jan/2024:10:30:00] "GET /admin" 403' > /tmp/test_logs/test.log

# 執行測試分析
export LMS_TARGET_LOG_DIR="/tmp/test_logs"
python lms_log_analyzer_v2.py
```

### 效能基準測試
```bash
# 測試大量日誌處理
time python lms_log_analyzer_v2.py

# 監控資源使用
/usr/bin/time -v python lms_log_analyzer_v2.py
```

---

## 版本更新與維護

### 版本資訊
- **v2.0** - 當前版本，支援向量搜尋和 LLM 分析
- **架構** - 模組化設計，支援水平擴展
- **相容性** - Python 3.8+, Linux 系統

### 定期維護
1. **每週** - 檢查日誌檔案大小和清理
2. **每月** - 更新 AI 模型和相依套件
3. **每季** - 評估和調整監控閾值
4. **每年** - 完整的安全稽核和效能評估

### 升級建議
- 定期更新 Python 套件：`pip install --upgrade -r requirements.txt`
- 監控 Gemini API 的新功能和定價變更
- 根據系統負載調整設定參數

---

## 授權與支援

本專案採用開源授權，歡迎社群貢獻和改進建議。

如需技術支援或有任何問題，請參考：
1. 專案文件和故障排除章節
2. GitHub Issues 回報問題
3. 社群討論和經驗分享

---

**注意：** 使用本工具前請確保已正確設定 API 金鑰和相關權限，並遵守相關的資料保護和隱私法規。
