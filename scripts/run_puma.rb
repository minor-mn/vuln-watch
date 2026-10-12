#!/usr/bin/env ruby

require "bundler/setup"
require "dotenv"

app_root = File.expand_path("..", __dir__)
Dotenv.load(File.join(app_root, ".env"))

master_key_file = File.join(app_root, "config/master.key")
unless ENV["RAILS_MASTER_KEY"] || File.readable?(master_key_file)
  abort "Missing Rails master key. Set RAILS_MASTER_KEY in .env or provide config/master.key."
end

ENV["RAILS_ENV"] ||= "production"
ENV["RAILS_LOG_TO_STDOUT"] ||= "1"
ENV["RAILS_SERVE_STATIC_FILES"] ||= "true"
ENV["APP_HOST"] ||= "an.umr.biz"
ENV["APP_PROTOCOL"] ||= "https"
ENV["PORT"] ||= "3000"
ENV["CVELIST_PATH"] ||= "vendor/cvelist"

queue_setting = ENV["SOLID_QUEUE_IN_PUMA"].to_s.strip.downcase
if queue_setting.empty? || %w[1 true yes on].include?(queue_setting)
  ENV["SOLID_QUEUE_IN_PUMA"] = "1"
else
  ENV.delete("SOLID_QUEUE_IN_PUMA")
end

puma = Gem.bin_path("puma", "puma")
exec(puma, "-C", File.join(app_root, "config/puma.rb"))
