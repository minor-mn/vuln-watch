#!/usr/bin/env ruby

require "bundler/setup"
require "dotenv"

app_root = File.expand_path("..", __dir__)
Dotenv.load(File.join(app_root, ".env"))

ENV["RAILS_ENV"] ||= "production"
ENV["RAILS_LOG_TO_STDOUT"] ||= "1"
ENV["RAILS_SERVE_STATIC_FILES"] ||= "true"

master_key_file = File.join(app_root, "config/master.key")
unless ENV["RAILS_MASTER_KEY"].to_s.match?(/\S/) || File.readable?(master_key_file)
  abort "Missing Rails master key. Set RAILS_MASTER_KEY in .env or provide config/master.key."
end

abort "Usage: with-env.rb COMMAND [ARG ...]" if ARGV.empty?
exec(*ARGV)
