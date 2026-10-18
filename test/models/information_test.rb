require "test_helper"

class InformationTest < ActiveSupport::TestCase
  setup do
    @now = Time.iso8601("2026-10-18T10:00:00Z")
    @sources = ENV.delete("INFORMATION_SOURCES")
  end
  teardown { ENV["INFORMATION_SOURCES"] = @sources }

  def item(source: "slashdot", number: 1, published_at: @now - 1.hour, **attributes)
    InformationItem.create!({ source:, url: "https://slashdot.org/story/#{number}", title: "AI security #{number}", body: "Report #{number}",
      published_at:, fetched_at: @now, summary: "AIの安全性を検証する取り組みが公開されました。", relevant: true,
      details: { "kind" => "discussion" } }.merge(attributes))
  end

  test "each source uses all recent posts or latest five and retains old rows" do
    9.times { |i| item(number: i, published_at: @now - i.hours) }
    item(number: 99, published_at: @now - 10.days)
    item(number: 100, published_at: @now + 1.hour)
    6.times { |i| item(source: "full_disclosure", number: i + 200, published_at: @now - i.days) }
    assert_equal 9, InformationItem.selected("slashdot", now: @now).size
    assert_equal 5, InformationItem.selected("full_disclosure", now: @now).size
    assert_equal 17, InformationItem.count
  end

  test "selection happens before relevance filtering and never replenishes unrelated posts" do
    5.times { |i| item(number: i, relevant: false) }
    item(number: 99, published_at: @now - 10.days)
    assert_empty InformationBriefing.new(sources: [ "slashdot" ], now: @now).external_items
  end

  test "Slashdot always belongs to topics and other security posts remain unjudged without matching CVE" do
    cve = ingest.cve
    cve.update!(current_judgement: "emergency")
    story = item(body: cve.identifier)
    fd = item(source: "full_disclosure", number: 2)
    assert_equal "topics", story.section(cve.identifier => cve)
    assert_equal "unknown", fd.section
    fd.update!(body: cve.identifier)
    assert_equal "emergency", fd.section(cve.identifier => cve)
  end

  test "source selection supports any subset including none and rejects unknown keys" do
    ENV["INFORMATION_SOURCES"] = "full_disclosure,slashdot"
    assert_equal %w[full_disclosure slashdot], InformationSources.enabled
    assert_equal [ "slashdot" ], InformationSources.select(%w[cve slashdot])
    assert_empty InformationSources.select("")
    assert_raises(ArgumentError) { InformationSources.select("reddit") }
    ENV["INFORMATION_SOURCES"] = ""
    assert_empty InformationSources.enabled
  end

  test "briefing preserves every item but reads only four in the opening and keeps replies private" do
    8.times { |i| item(number: i) }
    reply = item(source: "full_disclosure", number: 55, details: { "kind" => "mailing_list_reply" })
    InformationSourceState.create!(source: "slashdot", succeeded_at: @now)
    data = InformationBriefing.new(sources: %w[slashdot full_disclosure], now: @now).as_json
    assert_equal 8, data[:news][:items].size
    assert_equal 4, data[:news][:text].scan("AIの安全性").size
    assert_includes data[:news][:text], "ほかにも4件"
    assert_equal data[:news][:items].map { |row| row[:source][:url] }, data[:threads].map { |thread| thread["url"] || thread[:url] }
    assert_not_includes data[:news][:items].map { |row| row[:source][:url] }, reply.url
    assert data[:sources]["full_disclosure"][:stale]
  end

  class FakeHttp
    attr_reader :calls
    def initialize(responses)
      @responses, @calls = responses, []
    end
    def get(url, **options)
      @calls << [ url, options ]
      @responses.shift || raise("unexpected request")
    end
  end

  test "Atom uses published rather than updated and rejects future dates DTD and unsafe links" do
    body = <<~XML
      <feed xmlns="http://www.w3.org/2005/Atom">
        <entry><title>AI security</title><published>2026-10-01T00:00:00Z</published><updated>2026-10-18T00:00:00Z</updated><link href="https://slashdot.org/story/1"/><summary>&lt;p&gt;Full report&lt;/p&gt;</summary></entry>
        <entry><title>Future</title><published>2027-01-01T00:00:00Z</published><link href="https://slashdot.org/story/2"/></entry>
        <entry><title>Unsafe</title><published>2026-10-18T00:00:00Z</published><link href="https://slashdot.org.evil.test/story/3"/></entry>
      </feed>
    XML
    rows = InformationFeeds.new.parse_feed(body, "slashdot", now: @now)
    assert_equal 1, rows.size
    assert_equal Time.iso8601("2026-10-01T00:00:00Z"), rows.first[:published_at]
    assert_equal "Full report", rows.first[:body]
    assert_raises(InformationHttp::Error) { InformationFeeds.new.parse_feed("<!DOCTYPE x>" + body, "slashdot", now: @now) }
  end

  test "GitHub pagination covers all recent advisories and validates the next URL" do
    row = ->(n, published) { { type: "reviewed", withdrawn_at: nil, ghsa_id: "GHSA-aaaa-bbbb-#{n.to_s.rjust(4, '0')}", html_url: "https://github.com/advisories/GHSA-aaaa-bbbb-#{n.to_s.rjust(4, '0')}", summary: "Package issue", description: "Full details", published_at: published.iso8601, vulnerabilities: [ { package: { name: "sample" } } ] } }
    first = 100.times.map { |n| row.call(n, @now - 1.hour) }
    second = [ row.call(100, @now - 2.hours), row.call(101, @now - 2.days) ]
    http = FakeHttp.new([ InformationHttp::Response.new(body: first.to_json, next_url: "https://api.github.com/advisories?page=2"), InformationHttp::Response.new(body: second.to_json, next_url: nil) ])
    rows = InformationFeeds.new(http:).fetch("github_advisory", now: @now)
    assert_equal 102, rows.size
    assert rows.any? { |row| row[:published_at] == @now - 2.days }
    assert_equal 2, http.calls.size
    assert http.calls.all? { |_, options| options[:github] }
    assert_equal "sample", rows.first[:details].dig("vulnerabilities", 0, "package", "name")
    bad = FakeHttp.new([ InformationHttp::Response.new(body: first.to_json, next_url: "https://evil.test/advisories?page=2") ])
    assert_raises(InformationHttp::Error) { InformationFeeds.new(http: bad).fetch("github_advisory", now: @now) }
    assert_equal 1, bad.calls.size
  end

  test "Full Disclosure body excludes quotes and only descendant replies are collected" do
    url = "https://seclists.org/fulldisclosure/2026/Oct/1"
    html = <<~HTML
      <h1 class="m-title">Original</h1><!--X-Body-of-Message--><p>Original body</p><blockquote>quoted</blockquote><!--X-Body-of-Message-End-->
      <ul class="thread"><li><strong>Original</strong><ul><li><a href="2">Reply</a><ul><li><a href="3">Nested reply</a></li></ul></li></ul></li><li><a href="9">Unrelated</a></li></ul>
    HTML
    reply_html = ->(n) { "<h1 class='m-title'>Reply #{n}</h1><!--X-Body-of-Message-->Reply body<br>&gt; quote<br>Details<!--X-Body-of-Message-End--><ul class='thread'><li><strong>Reply</strong></li></ul>" }
    http = FakeHttp.new([ html, reply_html.call(2), reply_html.call(3) ].map { |body| InformationHttp::Response.new(body:, next_url: nil) })
    parser = InformationThreads.new(http:)
    message = parser.message(html, url)
    assert_equal "Original body", message[:text]
    assert_equal url, message[:parents]["https://seclists.org/fulldisclosure/2026/Oct/2"]
    result = parser.fetch(item(source: "full_disclosure", url:, details: { "kind" => "mailing_list" }))
    assert_equal "available", result["status"]
    assert_equal 2, result["comments"].size
    assert_equal 3, http.calls.size
    assert result["comments"].all? { |comment| comment["score"].nil? && !comment["text"].include?("> quote") }
  end

  test "Slashdot comments retain scores parents and truncation without scripts" do
    html = "<div id='comment_1'><span id='comment_score_1'>Score:5</span><a id='comment_link_1'>Title</a><div id='comment_body_1'>Opinion<script>BAD</script></div></div><ul id='commtree_1'><li><div id='comment_2'><div id='comment_body_2'>Reply<span class='substr'> ... </span></div></div></li></ul>"
    comments = InformationThreads.new.slashdot(html, "https://slashdot.org/story/1")
    assert_equal 2, comments.size
    assert_equal 5, comments.first["score"]
    assert_equal "Opinion", comments.first["text"]
    assert_equal "1", comments.last["parent_id"]
    assert comments.last["truncated"]
  end

  test "unavailable comments and advisory not applicable are distinct" do
    advisory = item(source: "github_advisory", details: { "kind" => "advisory" })
    assert_equal "not_applicable", InformationThreads.new(http: FakeHttp.new([])).fetch(advisory)["status"]
    fake = Object.new
    def fake.get(*) = raise InformationHttp::Error, "offline"
    assert_equal "unavailable", InformationThreads.new(http: fake).fetch(item(number: 9))["status"]
  end

  class SummaryClient
    attr_reader :calls
    def initialize
      @calls = []
    end
    def configured? = true
    def structured_output(**request)
      rows = JSON.parse(request.fetch(:input))
      @calls << rows
      items = rows.map do |row|
        { "id" => row["id"], "relevant" => true, "summary" => @calls.size == 1 && row == rows.first ? "長" * 80 : "AIの安全性を検証する仕組みが公開されました。" }
      end
      OpenaiClient::Response.new(output: { "items" => items }, raw: {})
    end
  end

  test "summaries repair only invalid rows preserve all topics and reuse unchanged inputs" do
    items = 11.times.map { |i| item(number: i) }
    reply = item(number: 99, source: "full_disclosure", details: { "kind" => "mailing_list_reply" })
    client = SummaryClient.new
    summarizer = InformationSummarizer.new(client:)
    summarizer.call(items + [ reply ])
    assert_equal [ 10, 1, 1 ], client.calls.map(&:size)
    assert items.all? { |row| row.reload.summary_digest.present? && row.summary.length <= 60 }
    assert_nil reply.reload.summary_digest
    summarizer.call(items)
    assert_equal 3, client.calls.size
    items.first.update!(body: "Updated body")
    summarizer.call(items)
    assert_equal 4, client.calls.size
  end

  class PartialSummaryClient < SummaryClient
    def initialize(invalid_id:, fail_repair: false)
      super()
      @invalid_id, @fail_repair = invalid_id, fail_repair
    end

    def structured_output(**request)
      rows = JSON.parse(request.fetch(:input))
      @calls << rows
      raise OpenaiClient::Error, "Repair request failed" if @fail_repair && @calls.size == 2

      items = rows.map do |row|
        { "id" => row["id"], "relevant" => true,
          "summary" => row["id"] == @invalid_id ? "" : "AIの安全性を検証する仕組みが公開されました。" }
      end
      OpenaiClient::Response.new(output: { "items" => items }, raw: {})
    end
  end

  test "successful summaries stay saved when another row remains invalid and are not requested next time" do
    successful = item(number: 1)
    invalid = item(number: 2)
    client = PartialSummaryClient.new(invalid_id: invalid.id)
    summarizer = InformationSummarizer.new(client:)

    assert_raises(OpenaiClient::Error) { summarizer.call([ successful, invalid ]) }
    assert_equal summarizer.digest(successful), successful.reload.summary_digest
    assert_equal "AIの安全性を検証する仕組みが公開されました。", successful.summary
    assert successful.relevant
    assert_nil invalid.reload.summary_digest

    assert_raises(OpenaiClient::Error) { summarizer.call([ successful.reload, invalid.reload ]) }
    assert_equal [ [ successful.id, invalid.id ], [ invalid.id ], [ invalid.id ], [ invalid.id ] ],
      client.calls.map { |rows| rows.map { |row| row.fetch("id") } }
  end

  test "successful summaries stay saved when the repair request fails" do
    successful = item(number: 1)
    invalid = item(number: 2)
    client = PartialSummaryClient.new(invalid_id: invalid.id, fail_repair: true)
    summarizer = InformationSummarizer.new(client:)

    error = assert_raises(OpenaiClient::Error) { summarizer.call([ successful, invalid ]) }
    assert_equal "Repair request failed", error.message
    assert_equal summarizer.digest(successful), successful.reload.summary_digest
    assert_nil invalid.reload.summary_digest
  end

  test "collector retains full raw posts and replies without exposing them as independent topics" do
    old = item(source: "full_disclosure", number: 500, title: "Withdrawn or removed", published_at: @now)
    fake_feeds = Object.new
    rows = [ { url: "https://seclists.org/fulldisclosure/2026/Oct/1", title: "Report", body: "DETAIL" * 400, published_at: @now, details: { "kind" => "mailing_list" } },
             { url: "https://seclists.org/fulldisclosure/2026/Oct/2", title: "Re: Report", body: "REPLY_ONLY", published_at: @now, details: { "kind" => "mailing_list_reply" } } ]
    fake_feeds.define_singleton_method(:fetch) { |*args, **options| rows }
    fake_threads = Object.new
    fake_threads.define_singleton_method(:fetch) { |item| { "url" => item.url, "status" => "empty", "comments" => [] } }
    InformationCollector.new(feeds: fake_feeds, summarizer: InformationSummarizer.new(client: SummaryClient.new), threads: fake_threads).call("full_disclosure", now: @now)
    assert_equal 3, InformationItem.count
    assert_not old.reload.listed
    assert_equal 2400, InformationItem.find_by!(title: "Report").body.length
    data = InformationBriefing.new(sources: [ "full_disclosure" ], now: @now).as_json
    assert_equal 1, data[:news][:items].size
    assert_equal 600, data[:news][:items].first[:article_summary].length
    assert_not_includes data[:news].to_json, "REPLY_ONLY"
  end

  test "collector prepares every fetched post and retains archives outside the rolling feed" do
    archive = item(source: "full_disclosure", number: 500, published_at: @now - 3.days)
    rows = (1..9).map do |i|
      { url: "https://seclists.org/fulldisclosure/2026/Oct/#{i}", title: "Report #{i}", body: "DETAIL",
        published_at: @now - (i == 9 ? 36 : i).hours, details: { "kind" => "mailing_list" } }
    end
    feeds = Object.new
    feeds.define_singleton_method(:fetch) { |*, **| rows }
    threads = Object.new
    threads.define_singleton_method(:fetch) { |row| { "url" => row.url, "status" => "empty", "comments" => [] } }
    InformationCollector.new(feeds:, summarizer: InformationSummarizer.new(client: SummaryClient.new), threads:).call("full_disclosure", now: @now)

    assert archive.reload.listed
    fetched = InformationItem.where(url: rows.map { |row| row[:url] })
    assert_equal 9, fetched.count
    assert fetched.all? { |row| row.summary_digest.present? && row.thread["status"] == "empty" }
    assert_equal 8, InformationBriefing.new(sources: [ "full_disclosure" ], now: @now).external_items.size
    selection = BriefingSelection.new(hours: "48", now: @now)
    assert_equal 9, InformationBriefing.new(sources: [ "full_disclosure" ], selection:).external_items.size
  end
end
