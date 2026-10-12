#!/usr/bin/env ruby

APP_ROOT = File.expand_path("..", __dir__)
APP_RUBY_VERSION = File.read(File.join(APP_ROOT, ".ruby-version")).strip
ENV["RBENV_ROOT"] = File.join(ENV.fetch("HOME"), ".anyenv/envs/rbenv")
ENV["RBENV_VERSION"] = APP_RUBY_VERSION
RBENV_VERSION_BIN = File.join(ENV.fetch("RBENV_ROOT"), "versions", APP_RUBY_VERSION, "bin")
abort "Ruby #{APP_RUBY_VERSION} is not installed under #{ENV.fetch('RBENV_ROOT')}" unless File.executable?(File.join(RBENV_VERSION_BIN, "ruby"))

ENV["PATH"] = "#{ENV.fetch('RBENV_ROOT')}/shims:#{ENV.fetch('RBENV_ROOT')}/bin:#{RBENV_VERSION_BIN}:#{ENV.fetch('PATH', '')}"
BUNDLE_ENV = {
  "BUNDLE_GEMFILE" => File.join(APP_ROOT, "Gemfile"),
  "BUNDLE_PATH" => File.join(APP_ROOT, "vendor/bundle"),
  "BUNDLE_WITHOUT" => "development:test",
  "BUNDLE_FROZEN" => "true"
}.freeze

def run!(*command, env: {})
  warn "$ #{command.join(' ')}"
  success = system(BUNDLE_ENV.merge(env), *command, chdir: APP_ROOT)
  abort "Command failed: #{command.first}" unless success
end

def running_from_scripts?
  pid_file = File.join(APP_ROOT, "tmp/pids/vuln-watch.puma.pid")
  return false unless File.file?(pid_file)

  pid = Integer(File.read(pid_file).strip, 10)
  process_env = File.binread("/proc/#{pid}/environ").split("\0")
  process_env.include?("VULN_WATCH_ROOT=#{APP_ROOT}")
rescue ArgumentError, SystemCallError
  false
end

was_running = running_from_scripts?
run!("git", "pull", "--ff-only", "origin", "main") unless ENV.delete("VULN_WATCH_ALREADY_PULLED")
run!("bundle", "install", "--jobs", "2", "--retry", "3")

rails_env = { "RAILS_ENV" => "production" }
run!("bundle", "exec", "ruby", "scripts/with-env.rb", "bundle", "exec", "rails", "db:prepare", env: rails_env)
run!("bundle", "exec", "ruby", "scripts/with-env.rb", "bundle", "exec", "rails", "assets:precompile", env: rails_env)

if was_running
  run!("scripts/restart")
else
  puts "Deployment complete. Puma was stopped before deployment and remains stopped."
end
