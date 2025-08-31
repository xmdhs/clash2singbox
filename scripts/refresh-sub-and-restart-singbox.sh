#!/bin/bash

# --- Configuration Variables ---
TEMPLATE_FILE="/home/ubuntu/clash2singbox/config-templ.json" # Clash模板文件路径
SUBSCRIBE_URL=""           # 你的订阅链接
OUTPUT_CONFIG="/home/ubuntu/clash2singbox/config.json"                 # 生成的singbox配置文件名
LOG_FILE="/home/ubuntu/clash2singbox/singbox_refresh.log"              # 脚本运行日志文件
SINGBOX_RUN_LOG="/home/ubuntu/clash2singbox/singbox_run.log"        # sing-box自身运行的日志文件 (可选，可改为 /dev/null)
REFRESH_INTERVAL_SECONDS=1800               # 刷新间隔，单位秒 (例如 1800秒 = 30分钟)
# -------------------------------

# --- SCRIPT SETUP ---
# 确保脚本总是在其所在目录下执行，这样相对路径 (如TEMPLATE_FILE, OUTPUT_CONFIG) 才能正确解析
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cd "$SCRIPT_DIR" || { echo "$(date '+%Y-%m-%d %H:%M:%S') - Error: Could not change to script directory '$SCRIPT_DIR'. Exiting." | tee -a "$LOG_FILE"; exit 1; }

# Function to log messages with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
    # tee -a 会将消息输出到标准输出 (方便crontab捕获邮件) 和日志文件
}

log "--- Script execution started ---"

# --- Pre-checks ---
# Check for clash2singbox existence
if ! command -v clash2singbox &> /dev/null; then
    log "Error: 'clash2singbox' command not found. Please ensure it's installed and in your PATH."
    exit 1
fi

# Check for sing-box existence
if ! command -v sing-box &> /dev/null; then
    log "Error: 'sing-box' command not found. Please ensure it's installed and in your PATH."
    exit 1
fi

# Check if template file exists
if [ ! -f "$TEMPLATE_FILE" ]; then
    log "Error: Template file '$TEMPLATE_FILE' not found. Please ensure the path is correct."
    exit 1
fi

# --- 1. Generate config and check for changes ---
log "Generating new config from template and subscription..."

OLD_CONFIG_CHECKSUM=""
if [ -f "$OUTPUT_CONFIG" ]; then
    OLD_CONFIG_CHECKSUM=$(md5sum "$OUTPUT_CONFIG" 2>/dev/null | awk '{print $1}')
    log "Existing config checksum: ${OLD_CONFIG_CHECKSUM:-'N/A (file corrupted or unreadable)'}"
else
    log "No existing config file '$OUTPUT_CONFIG' found. A new one will be created."
fi

# Execute clash2singbox
clash2singbox -template "$TEMPLATE_FILE" -url "$SUBSCRIBE_URL" -o "$OUTPUT_CONFIG"
if [ $? -ne 0 ]; then
    log "Error: Failed to generate config using clash2singbox. Please check your template, URL, and clash2singbox installation."
    log "Sing-box will NOT be restarted due to config generation failure."
    exit 1 # Exit with error, cron will typically notify
fi

NEW_CONFIG_CHECKSUM=$(md5sum "$OUTPUT_CONFIG" | awk '{print $1}')
log "New config checksum: $NEW_CONFIG_CHECKSUM"

RESTART_REQUIRED=false
if [ -z "$OLD_CONFIG_CHECKSUM" ]; then
    log "Config file was just created. Restarting sing-box."
    RESTART_REQUIRED=true
elif [ "$OLD_CONFIG_CHECKSUM" != "$NEW_CONFIG_CHECKSUM" ]; then
    log "Config file content has changed. Restarting sing-box."
    RESTART_REQUIRED=true
else
    log "Config file content is identical. No sing-box restart needed."
    # Even if config didn't change, we should check if sing-box is running.
    # This handles cases where sing-box crashed between cron runs.
    PIDS_RUNNING=$(pgrep -f "sing-box -c ${OUTPUT_CONFIG} run")
    if [ -z "$PIDS_RUNNING" ]; then
        log "Warning: sing-box process is not found running, even though config did not change. Attempting to start it."
        RESTART_REQUIRED=true
    else
        log "Sing-box is already running (PIDs: $PIDS_RUNNING)."
    fi
fi

# --- 2. Restart sing-box if required ---
if $RESTART_REQUIRED; then
    log "Attempting to restart sing-box..."

    # Find and kill any existing sing-box processes using this config
    PIDS_TO_KILL=$(pgrep -f "sing-box -c ${OUTPUT_CONFIG} run")
    if [ -n "$PIDS_TO_KILL" ]; then
        log "Stopping existing sing-box processes (PIDs: $PIDS_TO_KILL)..."
        # 使用 sudo 杀死进程
        kill $PIDS_TO_KILL
        sleep 2 # Give it a moment to terminate
        PIDS_LEFT=$(pgrep -f "sing-box -c ${OUTPUT_CONFIG} run")
        if [ -n "$PIDS_LEFT" ]; then
            log "Warning: Some sing-box processes ($PIDS_LEFT) did not terminate gracefully. Forcing kill."
            kill -9 $PIDS_LEFT
            sleep 1
        fi
    else
        log "No existing sing-box process found using this config."
    fi

    # Start new sing-box process
    log "Starting new sing-box: nohup sing-box -c $OUTPUT_CONFIG run > $SINGBOX_RUN_LOG 2>&1 &"
    # 使用 nohup 和 & 让 sing-box 在后台运行，并且脱离当前脚本的shell环境
    nohup sing-box -c "$OUTPUT_CONFIG" run > "$SINGBOX_RUN_LOG" 2>&1 &
    NEW_SINGBOX_PID=$! # Capture the PID of the last background process

    sleep 3 # Give sing-box a few seconds to start up

    # Verify if sing-box is running
    # We use pgrep with the exact command line to be sure it's *our* sing-box
    ACTUAL_RUNNING_PIDS=$(pgrep -f "sing-box -c ${OUTPUT_CONFIG} run")
    if [ -n "$ACTUAL_RUNNING_PIDS" ]; then
        log "New sing-box successfully started with PID(s): $ACTUAL_RUNNING_PIDS"
    else
        log "Error: sing-box does not seem to be running after start command."
        log "Please check '$SINGBOX_RUN_LOG' for sing-box's internal errors."
        exit 1 # Indicate failure, cron will typically notify
    fi
fi

log "--- Script execution finished ---"