#!/usr/bin/env bash
# ==============================================================================
# NovaShield Web Server Wrapper - Enhanced Restart Safety
# ==============================================================================
# This wrapper provides additional restart safety and logging for the web server
# Recommended usage: Use this instead of direct server.py for production

set -euo pipefail

NS_HOME="${HOME}/.novashield"
NS_LOGS="${NS_HOME}/logs"
NS_WWW="${NS_HOME}/www"
NS_PID="${NS_HOME}/.pids"
WEB_LOG="${NS_HOME}/web.log"
WRAPPER_LOG="${NS_LOGS}/web_wrapper.log"

# Ensure directories exist
mkdir -p "$NS_LOGS" "$NS_PID"

# Logging function
log_wrapper() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WRAPPER] $*" | tee -a "$WRAPPER_LOG" >&2
}

# Configuration - Enhanced for stability
MAX_RESTARTS=5          # Maximum restarts per hour
RESTART_WINDOW=3600     # 1 hour in seconds  
MIN_UPTIME=60          # Minimum uptime before considering restart successful
BACKOFF_BASE=5         # Base backoff time in seconds
MAX_BACKOFF=300        # Maximum backoff time (5 minutes)

# Enhanced resource monitoring
MEMORY_THRESHOLD=500   # MB - restart if server uses more than this
CPU_THRESHOLD=80       # % - restart if server uses more than this for 30s consecutively
CRASH_THRESHOLD=3      # Consecutive crashes before applying max backoff

# Get current timestamp
current_time() {
    date +%s
}

# Check if we've exceeded restart limits
check_restart_limits() {
    local now=$(current_time)
    local limit_file="${NS_PID}/restart_limits.txt"
    
    # Clean old restart records (older than RESTART_WINDOW)
    if [ -f "$limit_file" ]; then
        local temp_file=$(mktemp)
        while IFS= read -r line; do
            local restart_time=$(echo "$line" | cut -d' ' -f1)
            if [ $((now - restart_time)) -lt $RESTART_WINDOW ]; then
                echo "$line" >> "$temp_file"
            fi
        done < "$limit_file"
        mv "$temp_file" "$limit_file"
    fi
    
    # Count restarts in current window
    local restart_count=0
    if [ -f "$limit_file" ]; then
        restart_count=$(wc -l < "$limit_file")
    fi
    
    if [ "$restart_count" -ge $MAX_RESTARTS ]; then
        log_wrapper "CRITICAL: Exceeded restart limit ($restart_count/$MAX_RESTARTS in last hour). Refusing to restart."
        log_wrapper "Manual intervention required. Check ${WEB_LOG} and ${WRAPPER_LOG} for errors."
        return 1
    fi
    
    # Record this restart attempt
    echo "$(current_time) restart_attempt" >> "$limit_file"
    return 0
}

# Monitor server resource usage
monitor_server_resources() {
    local pid="$1"
    [ -z "$pid" ] && return 0
    
    # Get memory usage in MB
    local mem_mb=0
    if command -v ps >/dev/null 2>&1; then
        mem_mb=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{print int($1/1024)}' || echo 0)
    fi
    
    # Get CPU usage percentage (if available)
    local cpu_pct=0
    if command -v ps >/dev/null 2>&1; then
        cpu_pct=$(ps -o pcpu= -p "$pid" 2>/dev/null | awk '{print int($1)}' || echo 0)
    fi
    
    # Log high resource usage
    if [ "$mem_mb" -gt $MEMORY_THRESHOLD ]; then
        log_wrapper "WARNING: High memory usage detected: ${mem_mb}MB (threshold: ${MEMORY_THRESHOLD}MB)"
        # Don't restart immediately, just warn
    fi
    
    if [ "$cpu_pct" -gt $CPU_THRESHOLD ]; then
        log_wrapper "WARNING: High CPU usage detected: ${cpu_pct}% (threshold: ${CPU_THRESHOLD}%)"
        # Don't restart immediately, just warn  
    fi
    
    return 0
}

# Enhanced server health check
check_server_health() {
    local pid="$1"
    local start_time="$2"
    
    # Check if process is still running
    if ! kill -0 "$pid" 2>/dev/null; then
        local uptime=$(($(current_time) - start_time))
        if [ "$uptime" -lt 5 ]; then
            log_wrapper "CRITICAL: Server died within 5 seconds - likely configuration or dependency issue"
            return 2  # Critical failure
        elif [ "$uptime" -lt $MIN_UPTIME ]; then
            log_wrapper "ERROR: Server died after ${uptime}s (min uptime: ${MIN_UPTIME}s)"
            return 1  # Early failure
        else
            log_wrapper "INFO: Server stopped after ${uptime}s (normal runtime)"
            return 1  # Normal failure
        fi
    fi
    
    # Monitor resources
    monitor_server_resources "$pid"
    
    return 0  # Server is healthy
}

# Clean shutdown
cleanup() {
    log_wrapper "Wrapper received shutdown signal"
    if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log_wrapper "Gracefully stopping web server (PID $SERVER_PID)"
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        sleep 2
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            log_wrapper "Force killing web server (PID $SERVER_PID)"  
            kill -KILL "$SERVER_PID" 2>/dev/null || true
        fi
    fi
    rm -f "${NS_PID}/web.pid" 2>/dev/null || true
    exit 0
}

# Set up signal handlers
trap cleanup TERM INT

log_wrapper "NovaShield Web Server Wrapper started"
log_wrapper "Configuration: max_restarts=$MAX_RESTARTS, restart_window=${RESTART_WINDOW}s, min_uptime=${MIN_UPTIME}s"

restart_count=0
consecutive_crashes=0

while true; do
    # Check restart limits
    if ! check_restart_limits; then
        exit 1
    fi
    
    log_wrapper "Starting web server attempt #$((restart_count + 1))"
    start_time=$(current_time)
    
    # Start the server
    cd "$NS_WWW" || {
        log_wrapper "ERROR: Cannot change to web directory $NS_WWW"
        exit 1
    }
    
    # Enhanced server startup with better logging
    export PYTHONUNBUFFERED=1  # Ensure immediate log output
    python3 "${NS_WWW}/server.py" >> "$WEB_LOG" 2>&1 &
    SERVER_PID=$!
    
    # Write PID file
    echo "$SERVER_PID" > "${NS_PID}/web.pid"
    log_wrapper "Web server started with PID $SERVER_PID"
    
    # Monitor the server process
    while true; do
        health_status=$(check_server_health "$SERVER_PID" "$start_time")
        case $health_status in
            0)  # Server is healthy, continue monitoring
                sleep 10  # Check every 10 seconds
                ;;
            1)  # Normal failure, restart with backoff
                break
                ;;
            2)  # Critical failure, apply maximum backoff
                consecutive_crashes=$((consecutive_crashes + 1))
                if [ $consecutive_crashes -ge $CRASH_THRESHOLD ]; then
                    log_wrapper "CRITICAL: $consecutive_crashes consecutive critical failures - applying maximum backoff"
                fi
                break
                ;;
        esac
    done
    
    # Wait for process to fully exit if it's still running
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        wait $SERVER_PID 2>/dev/null || true
    fi
    exit_code=$?
    
    # Remove PID file
    rm -f "${NS_PID}/web.pid" 2>/dev/null || true
    
    end_time=$(current_time)
    uptime=$((end_time - start_time))
    
    log_wrapper "Web server exited with code $exit_code after ${uptime}s uptime"
    
    # Calculate backoff based on failure type and consecutive crashes
    if [ $uptime -ge $MIN_UPTIME ]; then
        log_wrapper "Server ran successfully for ${uptime}s, resetting backoff counters"
        restart_count=0
        consecutive_crashes=0
        backoff_time=$BACKOFF_BASE
    else
        restart_count=$((restart_count + 1))
        
        # Calculate exponential backoff with crash multiplier
        local crash_multiplier=1
        if [ $consecutive_crashes -ge $CRASH_THRESHOLD ]; then
            crash_multiplier=$((consecutive_crashes * 2))
        fi
        
        backoff_time=$((BACKOFF_BASE * restart_count * crash_multiplier))
        if [ $backoff_time -gt $MAX_BACKOFF ]; then
            backoff_time=$MAX_BACKOFF
        fi
        
        log_wrapper "Server failed quickly (${uptime}s < ${MIN_UPTIME}s), applying ${backoff_time}s backoff"
        if [ $backoff_time -gt 300 ]; then
            backoff_time=300  # Cap at 5 minutes
        fi
    fi
    
    # Exit codes that should not trigger restart
    case $exit_code in
        0) log_wrapper "Clean shutdown, exiting"; exit 0 ;;
        130) log_wrapper "Interrupted (Ctrl+C), exiting"; exit 0 ;;
        143) log_wrapper "Terminated (SIGTERM), exiting"; exit 0 ;;
    esac
    
    log_wrapper "Waiting ${backoff_time}s before restart..."
    sleep $backoff_time
done