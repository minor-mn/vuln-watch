require "test_helper"

class BriefingsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @sources = ENV["INFORMATION_SOURCES"]
    ENV["INFORMATION_SOURCES"] = "cve,github_advisory,full_disclosure,slashdot"
    %w[slashdot full_disclosure github_advisory].each do |source|
      InformationItem.create!(source:, title: "#{source} title", url: "https://example.test/#{source}", body: "BODY", summary: "短い紹介です。", relevant: true,
        published_at: 1.hour.ago, fetched_at: Time.current, details: { "kind" => "report" })
    end
    ingest
  end
  teardown { ENV["INFORMATION_SOURCES"] = @sources }

  test "API returns current DB data for four sources and never needs a prepared file" do
    get "/api/briefing"
    assert_response :success
    data = response.parsed_body
    assert_equal 1, data["version"]
    assert_equal 4, data.dig("news", "items").size
    assert_equal 4, data["threads"].size
    assert_equal "Slashdot", data.dig("news", "items").last.dig("source", "publisher")
    assert_equal "no-store", response.headers["Cache-Control"]
    assert_equal %w[cve full_disclosure github_advisory slashdot], data["sources"].keys.sort
    InformationItem.find_by!(source: "slashdot").update!(summary: "新しい要約です。")
    get "/api/briefing", params: { sources: "slashdot" }
    assert_equal "新しい要約です。", response.parsed_body.dig("news", "items", 0, "summary")
  end

  test "sources can be filtered or empty and invalid sources return 400" do
    get "/api/briefing", params: { sources: [ "slashdot", "full_disclosure" ] }
    assert_response :success
    assert_equal 2, response.parsed_body.dig("news", "items").size
    get "/api/briefing", params: { sources: "" }
    assert_empty response.parsed_body.dig("news", "items")
    get "/api/briefing", params: { sources: "reddit" }
    assert_response :bad_request
  end

  def create_post(source:, title:, at:, relevant: true, kind: "report")
    InformationItem.create!(source:, title:, url: "https://example.test/#{source}/#{title}", body: "BODY", summary: "短い紹介です。", relevant:,
      published_at: at, fetched_at: Time.current, details: { "kind" => kind })
  end

  test "hours selects saved history beyond 24 hours and enforces the exact boundary" do
    travel_to Time.current.change(usec: 0) do
      6.times { |i| create_post(source: "slashdot", title: "recent#{i}", at: (i + 2).hours.ago) }
      create_post(source: "slashdot", title: "boundary", at: 48.hours.ago)
      create_post(source: "slashdot", title: "too-old", at: 48.hours.ago - 1.second)
      create_post(source: "slashdot", title: "future", at: 1.second.from_now)

      get "/api/briefing", params: { sources: "slashdot", hours: 48 }
      assert_response :success
      news = response.parsed_body.fetch("news")
      titles = news["items"].map { |row| row.dig("source", "title") }
      assert_equal 8, titles.size
      assert_includes titles, "boundary"
      assert_not_includes titles, "too-old"
      assert_not_includes titles, "future"
      assert_equal 48, news["hours"]
      assert_nil news["limit"]
      assert_equal "per_source_window", news["selection_policy"]
      assert_equal 48.hours.ago, Time.iso8601(news["since"])
      get "/api/briefing", params: { sources: "slashdot" }
      assert_equal 7, response.parsed_body.dig("news", "items").size
      assert_equal "per_source_24h_or_latest_5", response.parsed_body.dig("news", "selection_policy")
    end
  end

  test "limit applies independently to eligible topics from all four sources" do
    %w[slashdot full_disclosure github_advisory].each do |source|
      3.times { |i| create_post(source:, title: "post#{i}", at: (i + 2).hours.ago) }
    end
    create_post(source: "slashdot", title: "unrelated", at: 1.minute.ago, relevant: false)
    create_post(source: "full_disclosure", title: "reply", at: 1.minute.ago, kind: "mailing_list_reply")
    3.times { |i| ingest(id: "CVE-2026-990#{i}", published: (i + 1).hours.ago.iso8601) }

    get "/api/briefing", params: { hours: 24, limit: 2 }
    assert_response :success
    data = response.parsed_body
    groups = data.dig("news", "items").group_by { |row| row.dig("source", "publisher") }
    assert_equal 4, groups.size
    assert groups.values.all? { |rows| rows.size == 2 }
    groups.each_value do |rows|
      dates = rows.map { |row| Time.iso8601(row.dig("source", "published_at")) }
      assert_equal dates.sort.reverse, dates
    end
    assert_equal data.dig("news", "items").map { |row| row.dig("source", "url") }, data["threads"].map { |row| row["url"] }
    assert_equal "Slashdot", data.dig("news", "items").last.dig("source", "publisher")
    assert_equal 2, data.dig("news", "limit")
  end

  test "explicit conditions never fill the window with older posts and limit alone uses 24 hours" do
    InformationItem.where(source: "full_disclosure").update_all(published_at: 3.days.ago)
    get "/api/briefing", params: { sources: "full_disclosure" }
    assert_equal 1, response.parsed_body.dig("news", "items").size
    get "/api/briefing", params: { sources: "full_disclosure", hours: 48 }
    assert_empty response.parsed_body.dig("news", "items")
    get "/api/briefing", params: { sources: "full_disclosure", limit: 10 }
    assert_empty response.parsed_body.dig("news", "items")
    assert_equal 24, response.parsed_body.dig("news", "hours")
    assert_equal 10, response.parsed_body.dig("news", "limit")
  end

  test "fractional hours work and malformed hours and limits return 400" do
    travel_to Time.current.change(usec: 0) do
      create_post(source: "slashdot", title: "half-hour", at: 30.minutes.ago)
      get "/api/briefing", params: { sources: "slashdot", hours: "0.5" }
      assert_response :success
      assert_equal [ "half-hour" ], response.parsed_body.dig("news", "items").map { |row| row.dig("source", "title") }
    end
    [ "", "0", "-1", "NaN", "Infinity", "1e300", "oops", [ "24" ], { "value" => "24" } ].each do |hours|
      get "/api/briefing", params: { hours: }
      assert_response :bad_request, "hours=#{hours.inspect}"
    end
    [ "", "0", "-1", "1.5", "oops", "9223372036854775808", [ "2" ], { "value" => "2" } ].each do |limit|
      get "/api/briefing", params: { limit: }
      assert_response :bad_request, "limit=#{limit.inspect}"
    end
  end

  test "index has source sections and ends with lowercase slashdot" do
    get root_path
    assert_response :success
    assert_select "section:last-child#slashdot article a", text: "slashdot title"
    assert_select "#slashdot h2", text: /\Aslashdot/
    assert_select "#emergency article a", text: "slashdot title", count: 0
    assert_select "#full_disclosure article a", text: "full_disclosure title"
    get root_path, params: { sources: [ "slashdot" ] }
    assert_select "#slashdot article", count: 1
    assert_select "#full_disclosure", count: 0
    assert_select "#unknown article", count: 0
    assert_select "#unknown td", count: 0
  end
end
