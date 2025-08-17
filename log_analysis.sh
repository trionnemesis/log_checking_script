#!/bin/bash

# ────────────────────────────
# 綜合日誌分析器 with Gemini (繁體中文優化版 v2)
# ────────────────────────────
# 此腳本會掃描以下兩類日誌，並透過批次和平行處理提升效率：
# 1. HTTP 錯誤日誌：指定目錄中的網頁伺服器日誌 (403, 404, 500, 503 等)
# 2. 系統安全日誌：/var/log 中的 secure、messages、maillog 檔案
# 新增功能：
# - 報告會自動以時間戳記命名並存放在指定目錄
# - 執行完畢後會估算並顯示本次 API 呼叫所使用的 token 總數

# ────────────────────────────
# 組態設定
# ────────────────────────────
# HTTP 日誌檔案存放目錄
TARGET_LOG_DIR="${LMS_TARGET_LOG_DIR:-/var/log/LMS_LOG}"

# 系統日誌目錄
SYSTEM_LOG_DIR="/var/log"

# 報告存放的目錄
REPORT_DIR="/var/log/report"

# 單次 API 呼叫中要分析的最大日誌行數（每個類別），用以控制 API 成本與效率
MAX_LINES_TO_ANALYZE=20

# 腳本最長執行時間（秒）
MAX_EXECUTION_TIME=600  # 10 分鐘

# HTTP 錯誤代碼設定 (正則表達式)
ERROR_CODES="403|404|500|503"

# 系統日誌關鍵字設定 - 用於識別可疑活動 (正則表達式)
SECURITY_KEYWORDS="Failed|Invalid|Authentication|denied|refused|error|warning|attack|intrusion|unauthorized|suspicious|brute|exploit"

# 將變數匯出，供子程序使用
export TARGET_LOG_DIR SYSTEM_LOG_DIR REPORT_DIR MAX_LINES_TO_ANALYZE ERROR_CODES MAX_EXECUTION_TIME SECURITY_KEYWORDS

# ────────────────────────────
# 前置檢查
# ────────────────────────────
if ! command -v gemini &> /dev/null; then
    echo "[錯誤] 找不到 'gemini' 命令列工具。"
    echo "請確認您已安裝並設定好 Google Cloud SDK。"
    exit 1
fi

if [ ! -d "$SYSTEM_LOG_DIR" ]; then
    echo "[錯誤] 找不到系統日誌目錄: $SYSTEM_LOG_DIR"
    exit 1
fi

# 檢查報告目錄是否可寫，如果不存在則嘗試建立
if [ ! -d "$REPORT_DIR" ]; then
    echo "報告目錄 '$REPORT_DIR' 不存在，正在嘗試建立..."
    if ! mkdir -p "$REPORT_DIR"; then
        echo "[錯誤] 無法建立報告目錄 '$REPORT_DIR'。"
        echo "請檢查權限，或使用適當的權限執行 (例如: sudo)。"
        exit 1
    fi
fi

if [ ! -w "$REPORT_DIR" ]; then
    echo "[錯誤] 報告目錄 '$REPORT_DIR' 不可寫入。"
    echo "請檢查權限，或使用適當的權限執行 (例如: sudo)。"
    exit 1
fi

# ────────────────────────────
# 核心分析函式 (注入到子 Shell 中)
# ────────────────────────────

# 函式：分析 HTTP 錯誤日誌
analyze_http_logs() {
    local http_analysis_output
    http_analysis_output=$(mktemp)
    trap 'rm -f "$http_analysis_output"' RETURN

    echo "=== 第一部分：HTTP 錯誤日誌分析 ===" > "$http_analysis_output"
    echo "" >> "$http_analysis_output"

    if [ ! -d "$TARGET_LOG_DIR" ]; then
        echo "HTTP 日誌目錄 $TARGET_LOG_DIR 不存在，跳過分析。" >> "$http_analysis_output"
        cat "$http_analysis_output"
        return
    fi

    echo "正在搜尋 HTTP 錯誤日誌..."
    local http_log_files
    http_log_files=$(find "$TARGET_LOG_DIR" -maxdepth 1 -type f \( -name "*.log" -o -name "*.gz" -o -name "*.bz2" \) -printf "%T@ %p\n" | sort -nr | head -n 5 | cut -d' ' -f2-)

    if [ -z "$http_log_files" ]; then
        echo "在 $TARGET_LOG_DIR 中找不到 HTTP 日誌檔案。" >> "$http_analysis_output"
        cat "$http_analysis_output"
        return
    fi

    echo "找到的 HTTP 日誌檔案:" >> "$http_analysis_output"
    echo "$http_log_files" | sed 's,^,  - ,' >> "$http_analysis_output"
    echo "" >> "$http_analysis_output"

    local http_unique_lines
    http_unique_lines=$( (
        while IFS= read -r log_file; do
            case "$log_file" in
                *.gz)  zgrep -E "\" ($ERROR_CODES) " "$log_file" || true ;;
                *.bz2) bzgrep -E "\" ($ERROR_CODES) " "$log_file" || true ;;
                *)     grep -E "\" ($ERROR_CODES) " "$log_file" || true ;;
            esac
        done <<< "$http_log_files"
    ) | sort -u | shuf -n "$MAX_LINES_TO_ANALYZE")

    if [ -z "$http_unique_lines" ]; then
        echo "未發現符合條件的 HTTP 錯誤日誌。" >> "$http_analysis_output"
        cat "$http_analysis_output"
        return
    fi

    local http_unique_count
    http_unique_count=$(echo "$http_unique_lines" | wc -l)
    echo "從中隨機選取 $http_unique_count 行唯一的 HTTP 錯誤日誌進行批次分析..." >> "$http_analysis_output"
    echo "--------------------------------------------------" >> "$http_analysis_output"
    echo "$http_unique_lines" >> "$http_analysis_output"
    echo "--------------------------------------------------" >> "$http_analysis_output"
    echo "" >> "$http_analysis_output"

    local prompt
    prompt=$(cat <<PROMPT_END
請扮演一位資深網路安全分析師。分析以下 ${http_unique_count} 行 HTTP 錯誤日誌，判斷其中是否存在異常或惡意行為（例如：目錄遍歷、SQL注入、跨站腳本攻擊、弱點掃描等）。請遵循以下格式回覆：
1.  **綜合評估**：總結這些日誌反映出的整體安全態勢和主要威脅類型。
2.  **詳細分析**：針對每一條可疑的日誌，提供 IP 位址、風險等級（高/中/低）、可疑行為描述，以及具體的應對建議。如果日誌無明顯風險，可以略過。
日誌列表如下：
\`\`\`
${http_unique_lines}
\`\`\`
PROMPT_END
)

    echo "[AI 批次分析結果]:" >> "$http_analysis_output"
    
    # 估算 Prompt Tokens
    local prompt_chars=$(echo -n "$prompt" | wc -c)
    local prompt_tokens=$(( (prompt_chars + 3) / 4 ))
    
    if result=$(echo "$prompt" | gemini 2>/dev/null); then
        # 估算 Response Tokens
        local result_chars=$(echo -n "$result" | wc -c)
        local result_tokens=$(( (result_chars + 3) / 4 ))
        TOTAL_TOKENS=$((TOTAL_TOKENS + prompt_tokens + result_tokens))
        
        echo "$result" >> "$http_analysis_output"
        echo "HTTP 日誌批次分析完成。"
    else
        TOTAL_TOKENS=$((TOTAL_TOKENS + prompt_tokens)) # 即使失敗也計入 Prompt
        echo "AI 分析失敗。可能是 API 呼叫錯誤或超時。" >> "$http_analysis_output"
    fi
    cat "$http_analysis_output"
}

# 函式：分析系統安全日誌
analyze_system_logs() {
    local sys_analysis_output
    sys_analysis_output=$(mktemp)
    trap 'rm -f "$sys_analysis_output"' RETURN

    echo "=== 第二部分：系統安全日誌分析 ===" > "$sys_analysis_output"
    echo "" >> "$sys_analysis_output"
    echo "正在搜尋系統安全日誌..."

    local system_log_files
    system_log_files=$(find "$SYSTEM_LOG_DIR" -maxdepth 1 -type f \( -name "secure*" -o -name "messages*" -o -name "maillog*" -o -name "auth.log*" \) -print0 | xargs -0 ls -t | head -n 5)

    if [ -z "$system_log_files" ]; then
        echo "無法找到或讀取任何系統日誌檔案 (如 secure, messages, maillog)。" >> "$sys_analysis_output"
        cat "$sys_analysis_output"
        return
    fi

    echo "找到的系統日誌檔案:" >> "$sys_analysis_output"
    echo "$system_log_files" | sed 's,^,  - ,' >> "$sys_analysis_output"
    echo "" >> "$sys_analysis_output"

    local system_unique_lines
    system_unique_lines=$(grep -ihE "($SECURITY_KEYWORDS)" $system_log_files 2>/dev/null | sort -u | shuf -n "$MAX_LINES_TO_ANALYZE")

    if [ -z "$system_unique_lines" ]; then
        echo "未在系統日誌中發現明顯的安全相關事件。" >> "$sys_analysis_output"
        cat "$sys_analysis_output"
        return
    fi
    
    local system_unique_count
    system_unique_count=$(echo "$system_unique_lines" | wc -l)
    echo "從中隨機選取 $system_unique_count 行可疑的系統日誌進行批次分析..." >> "$sys_analysis_output"
    echo "--------------------------------------------------" >> "$sys_analysis_output"
    echo "$system_unique_lines" >> "$sys_analysis_output"
    echo "--------------------------------------------------" >> "$sys_analysis_output"
    echo "" >> "$sys_analysis_output"

    local prompt
    prompt=$(cat <<PROMPT_END
請扮演一位資深系統管理員與安全專家。分析以下 ${system_unique_count} 行系統日誌，判斷是否存在安全威脅或系統異常。請遵循以下格式回覆：
1.  **綜合評估**：總結這些日誌反映出的整體系統狀態和潛在風險。
2.  **詳細分析**：針對每一條可疑的日誌，提供時間、服務名稱、風險等級（高/中/低）、事件描述，以及建議的處理措施。如果日誌僅為一般警告，可以簡要說明。
日誌列表如下：
\`\`\`
${system_unique_lines}
\`\`\`
PROMPT_END
)

    echo "[AI 批次分析結果]:" >> "$sys_analysis_output"
    
    # 估算 Prompt Tokens
    local prompt_chars=$(echo -n "$prompt" | wc -c)
    local prompt_tokens=$(( (prompt_chars + 3) / 4 ))

    if result=$(echo "$prompt" | gemini 2>/dev/null); then
        # 估算 Response Tokens
        local result_chars=$(echo -n "$result" | wc -c)
        local result_tokens=$(( (result_chars + 3) / 4 ))
        TOTAL_TOKENS=$((TOTAL_TOKENS + prompt_tokens + result_tokens))

        echo "$result" >> "$sys_analysis_output"
        echo "系統日誌批次分析完成。"
    else
        TOTAL_TOKENS=$((TOTAL_TOKENS + prompt_tokens)) # 即使失敗也計入 Prompt
        echo "AI 分析失敗。可能是 API 呼叫錯誤或超時。" >> "$sys_analysis_output"
    fi
    cat "$sys_analysis_output"
}


# ────────────────────────────
# 主要邏輯
# ────────────────────────────

# 建立一個臨時檔案來傳遞 token 總數
TOKEN_COUNT_FILE=$(mktemp)
trap 'rm -f "$TOKEN_COUNT_FILE"' EXIT

# 使用 timeout 確保腳本不會執行過久
timeout "$MAX_EXECUTION_TIME" bash <<EOF
# 將變數和函式傳遞給子 Shell
export TARGET_LOG_DIR="$TARGET_LOG_DIR"
export SYSTEM_LOG_DIR="$SYSTEM_LOG_DIR"
export REPORT_DIR="$REPORT_DIR"
export MAX_LINES_TO_ANALYZE="$MAX_LINES_TO_ANALYZE"
export ERROR_CODES="$ERROR_CODES"
export SECURITY_KEYWORDS="$SECURITY_KEYWORDS"
export TOKEN_COUNT_FILE="$TOKEN_COUNT_FILE"
$(declare -f analyze_http_logs)
$(declare -f analyze_system_logs)

set -e # 子 shell 中發生錯誤立即退出

# 初始化 token 計數器
TOTAL_TOKENS=0

echo "開始綜合日誌分析，時間: \$(date)"

# 產生帶有時間戳記的報告檔案路徑
FINAL_REPORT_PATH="\$REPORT_DIR/security_report_\$(date +%Y%m%d_%H%M%S).log"
echo "報告將儲存至: \$FINAL_REPORT_PATH"

# 初始化報告檔案
cat > "\$FINAL_REPORT_PATH" << REPORT_HEADER
============================================================
 綜合安全日誌分析報告 (Powered by Gemini AI) - 優化版
============================================================
 產生時間: \$(date)
 分析範圍: HTTP錯誤日誌 + 系統安全日誌
============================================================

REPORT_HEADER

# 建立兩個臨時檔案來存放平行分析的結果
HTTP_RESULT_FILE=\$(mktemp)
SYSTEM_RESULT_FILE=\$(mktemp)
trap 'rm -f "\$HTTP_RESULT_FILE" "\$SYSTEM_RESULT_FILE"' EXIT

# 平行執行 HTTP 和系統日誌分析
echo "正在平行啟動 HTTP 和系統日誌分析..."
analyze_http_logs > "\$HTTP_RESULT_FILE" &
HTTP_PID=\$!

analyze_system_logs > "\$SYSTEM_RESULT_FILE" &
SYSTEM_PID=\$!

# 等待兩個背景任務完成
wait \$HTTP_PID
wait \$SYSTEM_PID
echo "所有分析任務已完成。"

# 將分析結果寫入最終報告
cat "\$HTTP_RESULT_FILE" >> "\$FINAL_REPORT_PATH"
echo "" >> "\$FINAL_REPORT_PATH"
cat "\$SYSTEM_RESULT_FILE" >> "\$FINAL_REPORT_PATH"

# ────────────────────────────
# 產生綜合摘要
# ────────────────────────────
echo "" >> "\$FINAL_REPORT_PATH"
echo "=== 綜合安全評估摘要 ===" >> "\$FINAL_REPORT_PATH"
echo "" >> "\$FINAL_REPORT_PATH"

SUMMARY_CONTEXT=\$(cat "\$HTTP_RESULT_FILE" "\$SYSTEM_RESULT_FILE")

SUMMARY_PROMPT=\$(cat <<PROMPT_END
基於以下兩個獨立的分析報告（HTTP日誌分析和系統日誌分析），請提供一個高度概括的綜合安全狀況評估摘要。摘要應包含：
1.  **整體風險等級評估** (高/中/低/資訊)。
2.  **發現的主要安全威脅類型** (例如：外部掃描、登入嘗試失敗、設定錯誤等)。
3.  **最緊急的待辦事項** (1-3項)。
4.  **長期的預防與監控建議**。
請保持摘要簡潔、精準且具有指導性。
--- 分析報告上下文 ---
\${SUMMARY_CONTEXT}
--- 分析報告上下文結束 ---
PROMPT_END
)

echo "[AI 綜合安全評估]:" >> "\$FINAL_REPORT_PATH"

# 估算 Prompt Tokens
prompt_chars=\$(echo -n "\$SUMMARY_PROMPT" | wc -c)
prompt_tokens=\$(( (prompt_chars + 3) / 4 ))

if result=\$(echo "\$SUMMARY_PROMPT" | gemini 2>/dev/null); then
    # 估算 Response Tokens
    result_chars=\$(echo -n "\$result" | wc -c)
    result_tokens=\$(( (result_chars + 3) / 4 ))
    TOTAL_TOKENS=\$((TOTAL_TOKENS + prompt_tokens + result_tokens))
    
    echo "\$result" >> "\$FINAL_REPORT_PATH"
    echo "綜合評估完成。"
else
    TOTAL_TOKENS=\$((TOTAL_TOKENS + prompt_tokens)) # 即使失敗也計入 Prompt
    echo "綜合評估失敗，請手動檢視上述個別分析結果。" >> "\$FINAL_REPORT_PATH"
fi

# 報告結尾
cat >> "\$FINAL_REPORT_PATH" << REPORT_FOOTER

============================================================
 報告產生完畢
============================================================
 分析時間: \$(date)
 建議: 請定期執行此分析並關注高風險項目。
============================================================
REPORT_FOOTER

echo "綜合安全分析完成！報告已儲存至: \$FINAL_REPORT_PATH"

# 將最終的 token 總數寫入臨時檔案
echo "\$TOTAL_TOKENS" > "\$TOKEN_COUNT_FILE"

EOF

# 檢查 timeout 結果
TIMEOUT_STATUS=$?
if [ $TIMEOUT_STATUS -eq 124 ]; then
    echo "[錯誤] 腳本執行超過 $MAX_EXECUTION_TIME 秒，已逾時。"
    FINAL_REPORT_PATH_GUESS="$REPORT_DIR/security_report_*.log"
    # 即使超時，也嘗試保留部分報告
    if ls $FINAL_REPORT_PATH_GUESS 1> /dev/null 2>&1; then
        echo -e "\n\n[警告] 腳本執行超時，報告可能不完整。" >> $(ls -t $FINAL_REPORT_PATH_GUESS | head -1)
    fi
    exit 1
elif [ $TIMEOUT_STATUS -ne 0 ]; then
    echo "[錯誤] 腳本執行時發生未知錯誤，退出代碼: $TIMEOUT_STATUS。"
    exit $TIMEOUT_STATUS
fi

# 讀取並顯示 token 總數
FINAL_TOKEN_COUNT=$(cat "$TOKEN_COUNT_FILE")
echo ""
echo "============================================================"
echo " 本次執行估算使用 Token 總數: ${FINAL_TOKEN_COUNT} tokens"
echo " (此為估算值，基於 4 個字元 ≈ 1 token)"
echo "============================================================"
echo ""
echo "建議使用 'sudo' 權限執行以獲得完整的系統日誌存取權限。"
