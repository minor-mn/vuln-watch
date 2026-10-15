#!/usr/bin/env ruby

if $PROGRAM_NAME == __FILE__
  task_app_root = ENV.fetch("VULN_WATCH_ROOT", File.expand_path("..", __dir__))
  ENV["BUNDLE_GEMFILE"] = File.join(task_app_root, "Gemfile")
  ENV["BUNDLE_PATH"] ||= File.join(task_app_root, "vendor/bundle") if File.directory?(File.join(task_app_root, "vendor/bundle"))
  ENV["BUNDLE_WITHOUT"] ||= "development:test"
  require "bundler/setup"
end

require "json"
require "open3"
require "optparse"
require "fileutils"
require "time"

module DailyMatchedTextTranslation
  class Error < StandardError; end

  class CommandTranslator
    def initialize(command:, timeout: 300)
      @command = command
      @timeout = Float(timeout)
      raise Error, "Translation timeout must be positive" unless @timeout.positive?
    end

    def check!
      raise Error, "Translation command is not executable: #{@command}" unless File.file?(@command) && File.executable?(@command)
    end

    def translate(text)
      raise Error, "Original text is empty" unless text.is_a?(String) && !text.strip.empty?

      Open3.popen3(@command, text, "Japanese", pgroup: true) do |input, output, errors, process|
        input.close
        output_reader = Thread.new { output.read }
        error_reader = Thread.new { errors.read }

        unless process.join(@timeout)
          signal_group("TERM", process.pid)
          process.join(1)
          signal_group("KILL", process.pid)
          process.join
          output_reader.join
          error_reader.join
          raise Error, "Translation exceeded #{@timeout} seconds"
        end

        translated = output_reader.value.force_encoding(Encoding::UTF_8)
        diagnostic = error_reader.value.force_encoding(Encoding::UTF_8).scrub.strip
        unless process.value.success?
          raise Error, "Translation exited with #{process.value.exitstatus || process.value.termsig}: #{diagnostic[0, 500]}"
        end
        raise Error, "Translation returned invalid UTF-8" unless translated.valid_encoding?
        raise Error, "Translation returned empty output" if translated.strip.empty?

        translated.strip
      end
    rescue SystemCallError => error
      raise Error, "Cannot execute translation command: #{error.message}"
    end

    private
      def signal_group(signal, pid)
        Process.kill(signal, -pid)
      rescue Errno::ESRCH
        nil
      end
  end

  class Repository
    EMPTY_TRANSLATION = "(matched_text_ja IS NULL OR matched_text_ja ~ '^[[:space:]]*$')".freeze

    def initialize(connection)
      @connection = connection
    end

    def snapshot
      row = @connection.exec(<<~SQL).first
        SELECT COUNT(*) AS pending, COALESCE(MAX(id), 0) AS last_id
        FROM product_matches WHERE #{EMPTY_TRANSLATION}
      SQL
      { pending: row.fetch("pending").to_i, last_id: row.fetch("last_id").to_i }
    end

    def next_batch(after_id:, last_id:, size:)
      @connection.exec_params(<<~SQL, [ after_id, last_id, size ]).to_a
        SELECT id, matched_text FROM product_matches
        WHERE #{EMPTY_TRANSLATION} AND id > $1 AND id <= $2
        ORDER BY id LIMIT $3
      SQL
    end

    def store(id:, original:, translated:)
      @connection.exec_params(<<~SQL, [ translated, id, original ]).cmd_tuples == 1
        UPDATE product_matches SET matched_text_ja = $1, updated_at = CURRENT_TIMESTAMP
        WHERE id = $2 AND matched_text = $3 AND #{EMPTY_TRANSLATION}
      SQL
    end
  end

  class Batch
    def initialize(repository:, translator:, lock_path:, logger:)
      @repository = repository
      @translator = translator
      @lock_path = lock_path
      @logger = logger
    end

    def call(limit: nil, dry_run: false)
      stats = { processed: 0, translated: 0, failed: 0, skipped: 0 }
      FileUtils.mkdir_p(File.dirname(@lock_path))
      File.open(@lock_path, File::RDWR | File::CREAT, 0o600) do |lock|
        unless lock.flock(File::LOCK_EX | File::LOCK_NB)
          log("already_running")
          return stats.merge(already_running: true)
        end

        snapshot = @repository.snapshot
        log("started", snapshot.merge(limit: limit, dry_run: dry_run))
        return stats.merge(pending: snapshot[:pending], dry_run: true) if dry_run
        return stats if snapshot[:pending].zero?

        @translator.check!
        after_id = 0
        loop do
          remaining = limit && limit - stats[:processed]
          break if remaining && remaining <= 0

          rows = @repository.next_batch(after_id: after_id, last_id: snapshot[:last_id], size: [ 100, remaining || 100 ].min)
          break if rows.empty?

          rows.each do |row|
            after_id = row.fetch("id").to_i
            original = row.fetch("matched_text")
            stats[:processed] += 1
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            begin
              translated = @translator.translate(original)
              saved = @repository.store(id: after_id, original: original, translated: translated)
              stats[saved ? :translated : :skipped] += 1
              log(saved ? "translated" : "changed_or_already_translated", id: after_id,
                seconds: (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(3))
            rescue Error => error
              stats[:failed] += 1
              log("translation_failed", id: after_id, error: error.message[0, 600])
            end
          end
        end
        log("finished", stats)
        stats
      end
    end

    private
      def log(event, values = {})
        @logger.call({ time: Time.now.utc.iso8601, event: event }.merge(values))
      end
  end

  def self.main(argv)
    options = { limit: nil, dry_run: false }
    parser = OptionParser.new do |args|
      args.banner = "Usage: daily_translate_matched_texts.rb [--dry-run] [--limit N]"
      args.on("--dry-run", "Report pending records without translating or updating") { options[:dry_run] = true }
      args.on("--limit N", Integer, "Maximum records to attempt in this run") { |n| options[:limit] = n }
      args.on("--help", "Show usage") { puts args; return 0 }
    end
    parser.parse!(argv)
    raise Error, "Unexpected arguments: #{argv.join(' ')}" unless argv.empty?
    raise Error, "Limit must be positive" if options[:limit] && options[:limit] <= 0

    app_root = ENV.fetch("VULN_WATCH_ROOT", File.expand_path("..", __dir__))
    require "dotenv"
    require "pg"
    require "erb"
    require "yaml"
    Dotenv.load(File.join(app_root, ".env"))

    databases = YAML.safe_load(ERB.new(File.read(File.join(app_root, "config/database.yml"))).result, aliases: true)
    primary = databases.fetch("production").fetch("primary")
    connection_options = { connect_timeout: 10, application_name: "vuln-watch-daily-translation", options: "-c statement_timeout=15000" }
    connection_options[:options] += " -c default_transaction_read_only=on" if options[:dry_run]
    url = primary["url"] || ENV["DATABASE_URL"]
    connection = if url && !url.empty?
      PG.connect(url, connection_options)
    else
      PG.connect(**connection_options.merge(host: primary.fetch("host", "127.0.0.1"),
        port: primary.fetch("port", 5432), dbname: primary.fetch("database"), user: primary.fetch("username"), password: primary["password"]))
    end

    batch = Batch.new(repository: Repository.new(connection),
      translator: CommandTranslator.new(command: ENV.fetch("HYMT_TRANSLATE_SCRIPT", "/home/nacci/dev/mt2/translate.sh"),
        timeout: ENV.fetch("HYMT_TRANSLATE_TIMEOUT", "300")),
      lock_path: File.join(app_root, "tmp/daily_matched_text_translation.lock"),
      logger: ->(record) { puts JSON.generate(record); $stdout.flush })
    stats = batch.call(**options)
    stats[:failed].positive? ? 1 : 0
  rescue StandardError => error
    warn JSON.generate(time: Time.now.utc.iso8601, event: "fatal", error: error.class.name, message: error.message[0, 600])
    1
  ensure
    connection&.close
  end
end

exit DailyMatchedTextTranslation.main(ARGV) if $PROGRAM_NAME == __FILE__
