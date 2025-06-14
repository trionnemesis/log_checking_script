#!/bin/bash

# === 全域設定 ===
LOG_FILE="/var/log/server_monitor_gemini.log"
# 狀態檔案與冷卻時間設定
STATE_FILE="/tmp/monitor_last_alert.state"
COOLDOWN_SECONDS=14400  # 4 小時
# 🚨 重要：請替換成您的 API 金鑰，或從環境變數讀取。
# 建議將 API 金鑰儲存在環境變數中，例如：
# export GEMINI_API_KEY_ENVVAR="YOUR_API_KEY"
# 然後在腳本中使用 GEMINI_API_KEY="${GEMINI_API_KEY_ENVVAR}"
GEMINI_API_KEY_INPUT="GEMINI_API_KEY_ENVVAR" # 您的 API 金鑰

# 檢查 API 金鑰是否已設定
if [ -z "$GEMINI_API_KEY_INPUT" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - 錯誤：GEMINI_API_KEY 未設定。請在腳本中設定或使用環境變數。" | sudo tee -a "${LOG_FILE}"
    exit 1
fi

API_URL_GENERATE_CONTENT="https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${GEMINI_API_KEY_INPUT}"
API_URL_COUNT_TOKENS="https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:countTokens?key=${GEMINI_API_KEY_INPUT}"

# === 輔助函數 ===
# 函數：記錄訊息到日誌檔案和控制台
log_message() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${message}" | sudo tee -a "${LOG_FILE}"
}

# 函數：僅記錄訊息到日誌檔案
log_to_file_only() {
    local message="$1"
    # tee writes to stdout and file. Redirect tee's stdout to /dev/null.
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${message}" | sudo tee -a "${LOG_FILE}" > /dev/null
}

# 函數：呼叫 Gemini API 計算 Token 數量
# 輸入: $1 - 要計算 Token 的文本
# 輸出: Token 數量，或在失敗時輸出 0 並記錄錯誤
get_token_count() {
    local text_to_count="$1"
    local token_count=0 # 預設為 0 以防失敗

    # 構建 JSON payload
    local count_payload
    count_payload=$(printf '{
      "contents": [{
        "parts": [{
          "text": %s
        }]
      }]
    }' "$(jq -Rsa . <<< "$text_to_count")")

    log_to_file_only "準備發送給 countTokens API 的 Payload:\n${count_payload}"

    local count_response_json_content
    local count_http_status
    local count_curl_exit_code
    local temp_count_response_file

    temp_count_response_file=$(mktemp)
    count_http_status=$(curl -s -w "%{http_code}" -o "$temp_count_response_file" \
                              -X POST \
                              -H "Content-Type: application/json" \
                              -d "$count_payload" \
                              "$API_URL_COUNT_TOKENS")
    count_curl_exit_code=$?
    count_response_json_content=$(cat "$temp_count_response_file")
    rm "$temp_count_response_file"

    if [ "$count_curl_exit_code" -ne 0 ]; then
        log_to_file_only "[E] countTokens API Curl 命令失敗，退出碼: ${count_curl_exit_code}。"
        token_count=0
    elif [ "$count_http_status" -ne 200 ]; then
        log_to_file_only "[E] countTokens API 請求失敗。HTTP 狀態碼: ${count_http_status}。回應內容: ${count_response_json_content}"
        token_count=0
    elif [ -z "$count_response_json_content" ]; then
        log_to_file_only "[E] countTokens API 回應內容為空。HTTP 狀態碼: ${count_http_status}。"
        token_count=0
    else
        log_to_file_only "收到來自 countTokens API 的原始 JSON 回應：\n${count_response_json_content}"
        # 解析 totalTokens
        token_count=$(echo "$count_response_json_content" | jq -r '.totalTokens // 0')
        if ! [[ "$token_count" =~ ^[0-9]+$ ]]; then # 檢查是否為數字
            log_to_file_only "[E] 無法從 countTokens API 回應中解析 totalTokens，或解析結果非數字。設為 0。原始回應已記錄。"
            token_count=0
        fi
    fi
    echo "$token_count"
}


# === 前置檢查 ===
if ! command -v jq &> /dev/null; then
    echo "錯誤：jq 未安裝。請先安裝 jq (例如：sudo apt install jq 或 sudo yum install jq)。"
    # 嘗試記錄到日誌，如果 log_message 函數此時可用
    if type log_message &> /dev/null; then log_message "錯誤：jq 未安裝。"; fi
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "提示：此腳本建議以 sudo 權限執行，以便將日誌寫入 ${LOG_FILE}"
fi

log_message "腳本啟動。"

# === 基礎系統資訊收集 (已增強穩健性) ===
# CPU Usage
CPU_FROM_TOP_RAW=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' 2>/dev/null)
if [[ "$CPU_FROM_TOP_RAW" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    CPU="$CPU_FROM_TOP_RAW"
else
    CPU=0 # 預設為 0
    log_to_file_only "[W] 無法從 top 指令解析 CPU 使用率 ('${CPU_FROM_TOP_RAW}')，設為 0。"
fi

# RAM Usage
RAM_TOTAL_RAW=$(free -m | awk '/Mem:/ {print $2}' 2>/dev/null)
RAM_USED_RAW=$(free -m | awk '/Mem:/ {print $3}' 2>/dev/null)

RAM_TOTAL=${RAM_TOTAL_RAW:-0} # 預設為 0
RAM_USED=${RAM_USED_RAW:-0}   # 預設為 0

if [[ "$RAM_TOTAL" =~ ^[0-9]+$ && "$RAM_USED" =~ ^[0-9]+$ && "$RAM_TOTAL" -gt 0 ]]; then
    RAM_USAGE=$((RAM_USED * 100 / RAM_TOTAL))
else
    RAM_USAGE=0 # 預設為 0，如果無法計算
    log_to_file_only "[W] 無法計算 RAM 使用率 (Total: '${RAM_TOTAL_RAW}', Used: '${RAM_USED_RAW}')，設為 0。"
fi

# IO Wait
IO_WAIT_FROM_IOSTAT_RAW=$(iostat -c 1 2 | tail -n 2 | head -n 1 | awk '{print $4}' 2>/dev/null)
if [[ "$IO_WAIT_FROM_IOSTAT_RAW" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    IO_WAIT="$IO_WAIT_FROM_IOSTAT_RAW"
else
    IO_WAIT=0 # 預設為 0
    log_to_file_only "[W] 無法從 iostat 指令解析 IO Wait ('${IO_WAIT_FROM_IOSTAT_RAW}')，設為 0。"
fi

# Disk Usage
# DISK_USAGE_RAW 用於報告，應保留原始格式如 "XX%"
DISK_USAGE_RAW_FROM_DF=$(df -h / | awk 'NR==2 {print $5}' 2>/dev/null)
DISK_USAGE_RAW=${DISK_USAGE_RAW_FROM_DF:-"0%"} # 若 df 指令失敗，預設為 "0%"

DISK_PERCENT_TEMP=$(echo "$DISK_USAGE_RAW" | tr -d '%')
if [[ "$DISK_PERCENT_TEMP" =~ ^[0-9]+$ ]]; then
    DISK_PERCENT="$DISK_PERCENT_TEMP"
else
    DISK_PERCENT=0 # 預設為 0，如果 tr 失敗或輸入無效
    log_to_file_only "[W] 無法從磁碟使用率字串解析百分比 ('${DISK_USAGE_RAW}')，設為 0。"
fi

log_to_file_only "系統資訊收集完成：CPU=${CPU}%, RAM=${RAM_USAGE}%, IO_WAIT=${IO_WAIT}%, DISK=${DISK_USAGE_RAW} (Parsed Percent: ${DISK_PERCENT}%)"

# === 本地 RAG 式異常分析 ===
ANOMALY_REPORT=""
# 紀錄目前異常類型，供狀態檔案使用
ALERT_TYPE=""
# 使用 bc 進行浮點數比較，並確保 bc 的輸入是有效的
# bc 回傳 1 代表 true, 0 代表 false
CPU_OVER_THRESHOLD=$(echo "${CPU:-0} > 80" | bc -l 2>/dev/null)
[ "${CPU_OVER_THRESHOLD:-0}" -eq 1 ] && {
    ANOMALY_REPORT+="CPU 使用率過高 (${CPU}%)\n"
    ALERT_TYPE+="CPU_HIGH;"
}

[ "$RAM_USAGE" -gt 85 ] && {
    ANOMALY_REPORT+="記憶體使用率過高 (${RAM_USAGE}%)\n"
    ALERT_TYPE+="RAM_HIGH;"
}

IO_WAIT_OVER_THRESHOLD=$(echo "${IO_WAIT:-0} > 10" | bc -l 2>/dev/null)
[ "${IO_WAIT_OVER_THRESHOLD:-0}" -eq 1 ] && {
    ANOMALY_REPORT+="IO 等待過高 (${IO_WAIT}%)\n"
    ALERT_TYPE+="IO_WAIT_HIGH;"
}

[ "$DISK_PERCENT" -gt 85 ] && {
    ANOMALY_REPORT+="磁碟使用率過高 (${DISK_USAGE_RAW})\n"
    ALERT_TYPE+="DISK_HIGH;"
}


if [ -z "$ANOMALY_REPORT" ]; then
    log_message "系統狀態正常，略過分析。"
    echo "[+] 系統狀態正常，略過分析。"
    # 系統恢復正常時清除狀態檔案
    rm -f "$STATE_FILE"
    exit 0
fi

# === 狀態檔案檢查與冷卻邏輯 ===
CURRENT_TIME=$(date +%s)
if [ -f "$STATE_FILE" ]; then
    IFS=':' read -r LAST_ALERT_TYPE LAST_ALERT_TIME < "$STATE_FILE"
    if [ "$ALERT_TYPE" = "$LAST_ALERT_TYPE" ] && [ $((CURRENT_TIME - LAST_ALERT_TIME)) -lt $COOLDOWN_SECONDS ]; then
        log_message "${ALERT_TYPE} 異常持續中，冷卻期內，本次跳過 LLM 分析。"
        echo "${ALERT_TYPE} 異常持續中，冷卻期內，本次跳過 LLM 分析。"
        exit 0
    fi
fi

log_message "偵測到系統異常。"
log_to_file_only "異常摘要：\n${ANOMALY_REPORT}"
echo -e "[!] 偵測到異常，準備送出 Gemini API 分析...\n異常摘要：\n${ANOMALY_REPORT}"

# === Gemini API 設定與呼叫 ===
PROMPT="以下是伺服器的異常摘要：
${ANOMALY_REPORT}
目前執行的服務有 mysql 與 apache。
請依此評估是否需要重啟服務，請用清楚句子表達：例如『請重啟 mysql』或『請重啟 apache』。請僅提供建議，不要包含其他無關的對話。"

# 計算輸入 Token
INPUT_TOKEN_COUNT=$(get_token_count "$PROMPT")
log_message "輸入 Token 數量 (Prompt): ${INPUT_TOKEN_COUNT}"


# 構建 generateContent JSON payload
JSON_PAYLOAD_GENERATE_CONTENT=$(printf '{
  "contents": [{
    "parts": [{
      "text": %s
    }]
  }]
}' "$(jq -Rsa . <<< "$PROMPT")")

log_to_file_only "準備發送給 generateContent API 的 Prompt:\n${PROMPT}"
log_to_file_only "準備發送給 generateContent API 的 JSON Payload:\n${JSON_PAYLOAD_GENERATE_CONTENT}"

TEMP_RESPONSE_FILE=$(mktemp)
HTTP_STATUS=$(curl -s -w "%{http_code}" -o "$TEMP_RESPONSE_FILE" \
                  -X POST \
                  -H "Content-Type: application/json" \
                  -d "$JSON_PAYLOAD_GENERATE_CONTENT" \
                  "$API_URL_GENERATE_CONTENT")
CURL_EXIT_CODE=$?
GEMINI_RESPONSE_JSON_CONTENT=$(cat "$TEMP_RESPONSE_FILE")
rm "$TEMP_RESPONSE_FILE"

if [ "$CURL_EXIT_CODE" -ne 0 ]; then
    log_message "[E] generateContent API Curl 命令失敗，退出碼: ${CURL_EXIT_CODE}。"
    echo "[E] generateContent API Curl 命令失敗。詳細資訊已記錄到 ${LOG_FILE}"
    exit 1
fi

if [ "$HTTP_STATUS" -ne 200 ]; then
    log_message "[E] generateContent API 請求失敗。HTTP 狀態碼: ${HTTP_STATUS}。回應內容: ${GEMINI_RESPONSE_JSON_CONTENT}"
    echo "[E] generateContent API 請求失敗。HTTP 狀態碼: ${HTTP_STATUS}。詳細資訊已記錄到 ${LOG_FILE}"
    exit 1
fi

if [ -z "$GEMINI_RESPONSE_JSON_CONTENT" ]; then
    log_message "[E] generateContent API 回應內容為空。HTTP 狀態碼: ${HTTP_STATUS}。"
    echo "[E] generateContent API 回應內容為空。"
    exit 1
fi

log_to_file_only "收到來自 generateContent API 的原始 JSON 回應：\n${GEMINI_RESPONSE_JSON_CONTENT}"

RESPONSE=$(echo "$GEMINI_RESPONSE_JSON_CONTENT" | jq -r '.candidates[0].content.parts[0].text // "無法解析 Gemini 回應"')

if [ "$RESPONSE" == "無法解析 Gemini 回應" ] || [ -z "$RESPONSE" ]; then
    log_message "[E] 無法從 generateContent API 回應中解析文本，或解析結果為空。原始回應已記錄。"
    echo "[E] 無法從 generateContent API 回應中解析文本。詳細資訊已記錄到 ${LOG_FILE}"
    log_to_file_only "用於解析的原始 JSON (generateContent): ${GEMINI_RESPONSE_JSON_CONTENT}"
    exit 1
fi

# 計算輸出 Token
OUTPUT_TOKEN_COUNT=$(get_token_count "$RESPONSE")
log_message "輸出 Token 數量 (Response): ${OUTPUT_TOKEN_COUNT}"

log_message "Gemini API 分析結果已收到。"
log_to_file_only "Gemini API 分析結果 (純文字):\n${RESPONSE}"
echo -e "========= Gemini API 分析結果 =========\n${RESPONSE}\n===================================="

RECOMMENDED_ACTIONS=""
if echo "$RESPONSE" | grep -qi "重啟 mysql"; then
    RECOMMENDED_ACTIONS+="建議重啟 MySQL\n"
fi
if echo "$RESPONSE" | grep -qi "重啟 apache" || echo "$RESPONSE" | grep -qi "重啟 httpd"; then
    RECOMMENDED_ACTIONS+="建議重啟 Apache/httpd\n"
fi

if [ -n "$RECOMMENDED_ACTIONS" ]; then
    log_message "[Summary of Recommended Actions]\n${RECOMMENDED_ACTIONS}"
    echo -e "\n[Summary of Recommended Actions]\n${RECOMMENDED_ACTIONS}"
else
    log_message "Gemini API 未明確建議重啟任何監控中的服務。"
    echo "Gemini API 未明確建議重啟任何監控中的服務。"
fi

# 將此次異常類型與時間寫入狀態檔案
echo "${ALERT_TYPE}:$(date +%s)" > "$STATE_FILE"

log_message "腳本執行完畢。"
exit 0
