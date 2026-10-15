#!/usr/bin/env bash
set -euo pipefail
umask 0027

task_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
task_app_root="${VULN_WATCH_ROOT:-/home/nacci/dev/vuln-watch}"
IFS= read -r task_ruby_version < "${task_app_root}/.ruby-version"
task_ruby="${HOME}/.anyenv/envs/rbenv/versions/${task_ruby_version}/bin/ruby"
export VULN_WATCH_ROOT="${task_app_root}"

exec "${task_ruby}" "${task_dir}/daily_translate_matched_texts.rb" "$@"
