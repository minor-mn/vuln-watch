require "test_helper"

class FullDisclosureAnalyzerTest < ActiveSupport::TestCase
  BODY = "A remote attacker can execute code without authentication and with no user interaction.\nSecond paragraph.\n".freeze

  class Client
    attr_reader :calls, :model
    attr_accessor :output, :error, :configured

    def initialize
      @calls, @model, @configured = [], "test-model", true
      evidence = {
        "AV" => { "quote" => "remote attacker", "explanation" => "遠隔から到達できます。" },
        "PR" => { "quote" => "without authentication", "explanation" => "認証が不要です。" },
        "UI" => { "quote" => "no user interaction", "explanation" => "利用者の操作は不要です。" }
      }
      @output = { "body_ja" => "認証を必要としない遠隔の攻撃者がコードを実行できます。\n利用者の操作は不要です。\n第2段落。",
        "assessments" => [ { "subject" => "Sample vulnerability", "attack_vector" => "N", "privileges_required" => "N", "user_interaction" => "N", "evidence" => evidence } ] }
    end

    def configured? = @configured

    def structured_output(**request)
      @calls << request
      raise @error if @error
      OpenaiClient::Response.new(output: @output.deep_dup, raw: { "id" => "response-test" })
    end
  end

  def item(**attributes)
    InformationItem.create!({ source: "full_disclosure", title: "Report", url: "https://seclists.org/fulldisclosure/2026/Oct/1",
      body: "RSS excerpt", full_body: BODY, published_at: 1.day.ago, fetched_at: Time.current,
      details: { "kind" => "mailing_list" } }.merge(attributes))
  end

  test "stores full original translation metrics and evidence without sending only an excerpt" do
    post = item(full_body: BODY + ("Additional paragraph.\n" * 100))
    client = Client.new
    analysis = FullDisclosureAnalyzer.new(client:).analyze(post)
    assert_equal post.full_body, JSON.parse(client.calls.first[:input])["body"]
    assert_operator analysis.original_body.length, :>, 600
    assert_equal post.full_body, analysis.original_body
    assert_equal client.output["body_ja"], analysis.body_ja
    assert_equal %w[N N N], analysis.assessments.first.values_at("attack_vector", "privileges_required", "user_interaction")
    assert_equal "remote attacker", analysis.assessments.first.dig("evidence", "AV", "quote")
    assert_equal "test-model", analysis.model
    assert_equal analysis, post.current_full_disclosure_analysis
  end

  test "unchanged input and content restored to a prior version reuse saved analysis" do
    post = item
    client = Client.new
    analyzer = FullDisclosureAnalyzer.new(client:)
    first = analyzer.analyze(post)
    assert_equal first.id, analyzer.analyze(post).id
    assert_equal 1, client.calls.size
    post.update!(full_body: BODY + "Changed content")
    assert_nil post.current_full_disclosure_analysis
    second = analyzer.analyze(post)
    assert_not_equal first.id, second.id
    post.update!(full_body: BODY)
    assert_equal first.id, analyzer.analyze(post).id
    assert_equal 2, client.calls.size
    assert_equal 2, post.full_disclosure_analyses.count
  end

  test "missing or invented evidence becomes unknown rather than a confident value" do
    post = item
    client = Client.new
    client.output["assessments"].first["evidence"]["PR"]["quote"] = "Administrator login is required"
    analysis = FullDisclosureAnalyzer.new(client:).analyze(post)
    assert_equal "unknown", analysis.assessments.first["privileges_required"]
    assert_equal "", analysis.assessments.first.dig("evidence", "PR", "quote")
    assert_equal "N", analysis.assessments.first["attack_vector"]
  end

  test "different vulnerabilities keep separate metrics" do
    post = item
    client = Client.new
    other = client.output["assessments"].first.deep_dup
    other.merge!("subject" => "Second vulnerability", "attack_vector" => "L", "privileges_required" => "H", "user_interaction" => "R")
    client.output["assessments"] << other
    analysis = FullDisclosureAnalyzer.new(client:).analyze(post)
    assert_equal 2, analysis.assessments.size
    assert_equal %w[N N N], analysis.assessments.first.values_at("attack_vector", "privileges_required", "user_interaction")
    assert_equal %w[L H R], analysis.assessments.last.values_at("attack_vector", "privileges_required", "user_interaction")
  end

  test "failure preserves previous analysis and does not save incomplete translation" do
    post = item
    client = Client.new
    analyzer = FullDisclosureAnalyzer.new(client:)
    original = analyzer.analyze(post)
    post.update!(full_body: BODY + "new content")
    client.error = OpenaiClient::Error.new("API unavailable")
    assert_raises(OpenaiClient::Error) { analyzer.analyze(post) }
    assert_equal 1, post.full_disclosure_analyses.count
    assert_equal original.body_ja, post.full_disclosure_analyses.first.body_ja
    client.error = nil
    client.output["body_ja"] = ""
    assert_raises(OpenaiClient::Error) { analyzer.analyze(post) }
    assert_equal 1, post.full_disclosure_analyses.count
  end

  test "other sources replies missing bodies and missing configuration do not call OpenAI" do
    client = Client.new
    analyzer = FullDisclosureAnalyzer.new(client:)
    post = item(source: "github_advisory")
    assert_nil analyzer.analyze(post)
    post.update!(source: "full_disclosure", details: { "kind" => "mailing_list_reply" })
    assert_nil analyzer.analyze(post)
    post.update!(details: { "kind" => "mailing_list" }, full_body: nil)
    assert_nil analyzer.analyze(post)
    post.update!(full_body: BODY)
    client.configured = false
    assert_nil analyzer.analyze(post)
    assert_empty client.calls
  end

  test "original message retains quoted text and paragraphs for full translation" do
    post = item
    html = "<h1 class='m-title'>Report</h1><!--X-Body-of-Message--><p>First paragraph.</p><p>Second paragraph.</p><blockquote>Quoted detail.</blockquote><!--X-Body-of-Message-End--><ul class='thread'><li><strong>Report</strong></li></ul>"
    http = Object.new
    http.define_singleton_method(:get) { |*| InformationHttp::Response.new(body: html, next_url: nil) }
    parser = InformationThreads.new(http:)
    result = parser.fetch(post)
    assert_includes result["original_body"], "Quoted detail."
    assert_match(/First paragraph\.\n+Second paragraph\./, result["original_body"])
    assert_empty result["comments"]
    assert_not_includes parser.message(html, post.url)[:text], "Quoted detail."
  end
end
