require "minitest/autorun"
require "tmpdir"
require "rbconfig"
require_relative "../daily_translate_matched_texts"

class TranslationCommandTest < Minitest::Test
  def setup
    @directory = Dir.mktmpdir("translation command ")
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def command(body, timeout: 5)
    path = File.join(@directory, "fake translator")
    File.write(path, "#!#{RbConfig.ruby}\n" + body)
    File.chmod(0o700, path)
    DailyMatchedTextTranslation::CommandTranslator.new(command: path, timeout: timeout)
  end

  def test_passes_untrusted_text_as_one_literal_argument
    marker = File.join(@directory, "should-not-exist")
    source = "$(touch #{marker}); 'quoted' \"text\"\nnext line"
    translator = command('require "json"; puts JSON.generate(ARGV)')
    assert_equal [ source, "Japanese" ], JSON.parse(translator.translate(source))
    refute File.exist?(marker)
  end

  def test_rejects_failed_and_empty_translations
    error = assert_raises(DailyMatchedTextTranslation::Error) do
      command('warn "generation incomplete"; exit 2').translate("hello")
    end
    assert_match "generation incomplete", error.message
    assert_raises(DailyMatchedTextTranslation::Error) { command('puts " "').translate("hello") }
  end

  def test_timeout_terminates_the_child_process
    pidfile = File.join(@directory, "pid")
    translator = command("File.write(#{pidfile.inspect}, Process.pid); sleep 20", timeout: 2)
    assert_raises(DailyMatchedTextTranslation::Error) { translator.translate("hello") }
    pid = Integer(File.read(pidfile))
    assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
  end
end

class TranslationBatchTest < Minitest::Test
  def setup
    skip "Set VULN_WATCH_TRANSLATION_TEST_DATABASE_URL for PostgreSQL integration tests" unless ENV["VULN_WATCH_TRANSLATION_TEST_DATABASE_URL"]
    require "pg"
    @connection = PG.connect(ENV.fetch("VULN_WATCH_TRANSLATION_TEST_DATABASE_URL"))
    raise "Refusing to modify a non-test database" unless @connection.db == "vuln_watch_translation_test"
    @connection.exec("DROP TABLE IF EXISTS product_matches")
    @connection.exec(<<~SQL)
      CREATE TABLE product_matches (
        id BIGSERIAL PRIMARY KEY, matched_text TEXT NOT NULL,
        matched_text_ja TEXT, updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      )
    SQL
    @directory = Dir.mktmpdir("translation-batch")
    @repository = DailyMatchedTextTranslation::Repository.new(@connection)
    @events = []
  end

  def teardown
    @connection&.close
    FileUtils.remove_entry(@directory) if @directory
  end

  def add(text, japanese = nil)
    @connection.exec_params("INSERT INTO product_matches(matched_text, matched_text_ja) VALUES($1,$2) RETURNING id", [ text, japanese ]).first.fetch("id").to_i
  end

  def japanese(id)
    @connection.exec_params("SELECT matched_text_ja FROM product_matches WHERE id=$1", [ id ]).first.fetch("matched_text_ja")
  end

  def translator(&block)
    Object.new.tap do |client|
      client.define_singleton_method(:check!) { true }
      client.define_singleton_method(:translate) { |text| block.call(text) }
    end
  end

  def batch(client)
    DailyMatchedTextTranslation::Batch.new(repository: @repository, translator: client,
      lock_path: File.join(@directory, "batch.lock"), logger: ->(event) { @events << event })
  end

  def test_fills_null_empty_and_whitespace_but_preserves_existing_translations
    ids = [ add("first"), add("second", ""), add("third", " \n\t") ]
    existing = add("fourth", "既存の訳")
    calls = []
    result = batch(translator { |text| calls << text; "訳: #{text}" }).call
    assert_equal 3, result[:translated]
    assert_equal %w[first second third], calls
    assert_equal [ "訳: first", "訳: second", "訳: third" ], ids.map { |id| japanese(id) }
    assert_equal "既存の訳", japanese(existing)
    assert_equal 0, batch(translator { raise "Already translated" }).call[:processed]
  end

  def test_failure_leaves_the_record_empty_and_continues
    first = add("bad")
    second = add("good")
    client = translator do |text|
      raise DailyMatchedTextTranslation::Error, "failed" if text == "bad"
      "正常な訳"
    end
    result = batch(client).call
    assert_equal 1, result[:failed]
    assert_equal 1, result[:translated]
    assert_nil japanese(first)
    assert_equal "正常な訳", japanese(second)
  end

  def test_does_not_overwrite_an_openai_translation_written_during_generation
    id = add("original")
    connection = @connection
    result = batch(translator do |_text|
      connection.exec_params("UPDATE product_matches SET matched_text_ja=$1 WHERE id=$2", [ "OpenAI の訳", id ])
      "ローカルの訳"
    end).call
    assert_equal 1, result[:skipped]
    assert_equal "OpenAI の訳", japanese(id)
  end

  def test_does_not_save_a_translation_if_the_original_changed
    id = add("old original")
    connection = @connection
    result = batch(translator do |_text|
      connection.exec_params("UPDATE product_matches SET matched_text=$1 WHERE id=$2", [ "new original", id ])
      "古い原文の訳"
    end).call
    assert_equal 1, result[:skipped]
    assert_nil japanese(id)
  end

  def test_overlapping_batches_never_run_a_second_translation
    add("original")
    nested = nil
    calls = 0
    inner = batch(translator { raise "Must not execute concurrently" })
    outer = batch(translator do |_text|
      calls += 1
      nested = inner.call
      "訳"
    end)
    assert_equal 1, outer.call[:translated]
    assert nested[:already_running]
    assert_equal 1, calls
  end

  def test_snapshot_does_not_keep_adding_new_rows_to_the_run
    first = add("existing")
    next_id = nil
    insert = method(:add)
    result = batch(translator do |_text|
      next_id = insert.call("arrived later")
      "訳"
    end).call
    assert_equal 1, result[:translated]
    assert_equal "訳", japanese(first)
    assert_nil japanese(next_id)
  end

  def test_dry_run_and_limit
    first = add("one")
    second = add("two")
    preview = batch(translator { raise "Dry run must not translate" }).call(dry_run: true)
    assert_equal 2, preview[:pending]
    assert_nil japanese(first)
    result = batch(translator { "訳" }).call(limit: 1)
    assert_equal 1, result[:translated]
    assert_equal "訳", japanese(first)
    assert_nil japanese(second)
  end
end
