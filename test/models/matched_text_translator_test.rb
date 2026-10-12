require "test_helper"

class MatchedTextTranslatorTest < ActiveSupport::TestCase
  test "translates untranslated matches once" do
    client = FakeOpenaiClient.new(translation: "Postgres の不具合。")
    cve = ingest(vendor: "acme", product: "widget", description: "A flaw in Postgres.").cve
    translator = MatchedTextTranslator.new(client:)

    translator.translate(cve)
    assert_equal "Postgres の不具合。", cve.product_matches.reload.sole.matched_text_ja

    translator.translate(cve)
    assert_equal 1, client.calls.size
  end

  test "translates again when the matched text changes" do
    client = FakeOpenaiClient.new
    cve = ingest(vendor: "acme", product: "widget", description: "A flaw in Postgres.").cve
    translator = MatchedTextTranslator.new(client:)
    translator.translate(cve)

    match = cve.product_matches.reload.sole
    match.update!(matched_text: "Another flaw in Postgres.")
    assert_nil match.matched_text_ja

    translator.translate(cve)
    assert_equal 2, client.calls.size
    assert_equal "訳", match.reload.matched_text_ja
  end

  test "does nothing when OpenAI is not configured" do
    client = FakeOpenaiClient.new(configured: false)
    cve = ingest.cve

    MatchedTextTranslator.new(client:, logger: Logger.new(nil)).translate(cve)
    assert_empty client.calls
    assert_nil cve.product_matches.reload.first.matched_text_ja
  end
end
