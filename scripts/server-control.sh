#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_ROOT"
PID_DIR="$APP_ROOT/tmp/pids"
PID_FILE="$PID_DIR/vuln-watch.puma.pid"
LOCK_FILE="$PID_DIR/vuln-watch.control.lock"
LOG_FILE="$APP_ROOT/log/puma.log"

umask 0027
mkdir -p "$PID_DIR"
command -v flock >/dev/null || {
  echo "flock is required to serialize server control operations." >&2
  exit 1
}
exec 9>"$LOCK_FILE"
flock 9

if [[ ! -r "$APP_ROOT/.ruby-version" ]]; then
  echo "Missing Ruby version file: $APP_ROOT/.ruby-version" >&2
  exit 1
fi
IFS= read -r ruby_version < "$APP_ROOT/.ruby-version"
export RBENV_ROOT="$HOME/.anyenv/envs/rbenv"
export RBENV_VERSION="$ruby_version"
PATH="$HOME/.anyenv/bin:$RBENV_ROOT/bin:$RBENV_ROOT/shims:$RBENV_ROOT/versions/$ruby_version/bin:$PATH"
export PATH
if [[ ! -x "$RBENV_ROOT/versions/$ruby_version/bin/bundle" ]]; then
  echo "Ruby $ruby_version is not installed under $RBENV_ROOT" >&2
  exit 1
fi

export BUNDLE_GEMFILE="$APP_ROOT/Gemfile"
export BUNDLE_PATH="${BUNDLE_PATH:-$APP_ROOT/vendor/bundle}"
export BUNDLE_WITHOUT="${BUNDLE_WITHOUT:-development:test}"
export RAILS_ENV="${RAILS_ENV:-production}"
export RAILS_LOG_TO_STDOUT="${RAILS_LOG_TO_STDOUT:-1}"
export RAILS_SERVE_STATIC_FILES="${RAILS_SERVE_STATIC_FILES:-true}"
export VULN_WATCH_ROOT="$APP_ROOT"

process_belongs_to_app() {
  local pid="$1"
  local process_env="/proc/$pid/environ"

  [[ -r "$process_env" ]] || return 1
  tr '\0' '\n' < "$process_env" | grep -Fqx "VULN_WATCH_ROOT=$APP_ROOT"
}

read_pid() {
  local pid=""
  [[ -f "$PID_FILE" ]] || return 1
  IFS= read -r pid < "$PID_FILE" || true
  [[ "$pid" =~ ^[0-9]+$ ]] || {
    echo "Invalid PID file: $PID_FILE" >&2
    return 2
  }
  printf '%s\n' "$pid"
}

write_pid() {
  local pid="$1"
  local temp_file="$PID_FILE.tmp.$$"
  printf '%s\n' "$pid" > "$temp_file"
  mv -f -- "$temp_file" "$PID_FILE"
}

start_server() {
  local pid=""

  [[ -r "$APP_ROOT/.env" ]] || {
    echo "Missing readable .env: $APP_ROOT/.env" >&2
    return 1
  }
  command -v bundle >/dev/null || {
    echo "Bundler is not on PATH." >&2
    return 1
  }

  if pid="$(read_pid)"; then
    if kill -0 "$pid" 2>/dev/null; then
      if process_belongs_to_app "$pid"; then
        echo "vuln-watch is already running (PID $pid)."
        return 0
      fi
      echo "PID $pid is in use by another process; refusing to signal it." >&2
      return 1
    fi
    rm -f "$PID_FILE"
  else
    local read_status=$?
    [[ "$read_status" -eq 1 ]] || return "$read_status"
  fi

  mkdir -p "$PID_DIR" "$APP_ROOT/log"
  nohup bundle exec ruby "$APP_ROOT/scripts/run_puma.rb" \
    9>&- >> "$LOG_FILE" 2>&1 </dev/null &
  pid=$!
  write_pid "$pid"

  for _ in {1..10}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$PID_FILE"
      echo "Puma exited during startup. See $LOG_FILE" >&2
      return 1
    fi
    if process_belongs_to_app "$pid"; then
      echo "Launched Puma (PID $pid). Solid Queue runs inside it unless .env disables it."
      return 0
    fi
    sleep 1
  done

  echo "Puma is still starting (PID $pid). See $LOG_FILE for output."
}

stop_server() {
  local pid=""
  local read_status=0

  if pid="$(read_pid)"; then
    :
  else
    read_status=$?
    if [[ "$read_status" -eq 1 ]]; then
      echo "vuln-watch is not running (no PID file)."
      return 0
    fi
    return "$read_status"
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$PID_FILE"
    echo "Removed stale PID file."
    return 0
  fi
  if ! process_belongs_to_app "$pid"; then
    echo "PID $pid is in use by another process; refusing to signal it." >&2
    return 1
  fi

  kill -TERM "$pid"
  for _ in {1..30}; do
    if ! kill -0 "$pid" 2>/dev/null || ! process_belongs_to_app "$pid"; then
      rm -f "$PID_FILE"
      echo "Stopped vuln-watch (PID $pid)."
      return 0
    fi
    sleep 1
  done

  echo "Puma did not stop within 30 seconds; PID $pid remains running." >&2
  return 1
}

case "${1:-}" in
  start)
    start_server
    ;;
  stop)
    stop_server
    ;;
  restart)
    stop_server
    start_server
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}" >&2
    exit 2
    ;;
esac
