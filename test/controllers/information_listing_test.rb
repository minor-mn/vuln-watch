require "test_helper"
require "uri"

class InformationListingTest < ActionDispatch::IntegrationTest
  setup do
    @sources = ENV["INFORMATION_SOURCES"]
    ENV["INFORMATION_SOURCES"] = "cve,github_advisory,full_disclosure,slashdot"
  end
  teardown { ENV["INFORMATION_SOURCES"] = @sources }

  def create_posts(source, count, days_ago: 3)
    count.times.map do |i|
      InformationItem.create!(source:, url: "https://example.test/#{source}/#{i}", title: "#{source} #{i}",
        body: "Report", summary: "検証結果が公開されました。", relevant: true,
        published_at: days_ago.days.ago - i.minutes, fetched_at: Time.current, details: { "kind" => "report" })
    end
  end

  test "Full Disclosure shows all fifteen saved reports while API keeps its latest-five default" do
    create_posts("full_disclosure", 15)
    get root_path, params: { sources: "full_disclosure" }
    assert_response :success
    assert_select "#full_disclosure h2", text: /Full Disclosure\s+15 件/
    assert_select "#full_disclosure article", count: 15
    assert_select "#full_disclosure", text: /1–15\s+\/ 15 件（1 \/ 1 ページ）/
    assert_select "#cve, #github_advisory, #slashdot", count: 0
    get "/api/briefing", params: { sources: "full_disclosure" }
    assert_equal 5, response.parsed_body.dig("news", "items").size
  end

  test "each source has its own heading and independent twenty-item pagination" do
    %w[github_advisory full_disclosure slashdot].each { |source| create_posts(source, 25) }
    get root_path, params: { sources: %w[github_advisory full_disclosure slashdot], full_disclosure_page: 2 }
    assert_response :success
    assert_select "#github_advisory h2", text: /GitHub Advisory Database\s+25 件/
    assert_select "#full_disclosure h2", text: /Full Disclosure\s+25 件/
    assert_select "#slashdot h2", text: /\Aslashdot\s+25 件/
    assert_select "section:last-child#slashdot"
    assert_select "#topics", count: 0
    assert_select "#github_advisory article", count: 20
    assert_select "#full_disclosure article", count: 5
    assert_select "#slashdot article", count: 20
    assert_select "#full_disclosure article a", text: "full_disclosure 20"
    assert_select "#full_disclosure article a", text: "full_disclosure 0", count: 0
    assert_select "#full_disclosure nav a[rel=prev]" do |links|
      uri = URI(links.first["href"])
      query = Rack::Utils.parse_nested_query(uri.query)
      assert_equal "1", query["full_disclosure_page"]
      assert_equal %w[github_advisory full_disclosure slashdot], query["sources"]
      assert_equal "full_disclosure", uri.fragment, links.first["href"]
    end
    assert_select "#github_advisory nav a[rel=next]"
    assert_select "#slashdot nav a[rel=next]"
    assert_select "#full_disclosure nav a[rel=next]", count: 0
  end

  test "pages clamp to existing pages and unavailable unrelated replies and future rows stay hidden" do
    create_posts("full_disclosure", 23)
    hidden = InformationItem.find_by!(title: "full_disclosure 1")
    hidden.update!(relevant: false)
    InformationItem.find_by!(title: "full_disclosure 2").update!(listed: false)
    InformationItem.find_by!(title: "full_disclosure 3").update!(details: { "kind" => "mailing_list_reply" })
    InformationItem.find_by!(title: "full_disclosure 4").update!(published_at: 1.day.from_now)
    get root_path, params: { sources: "full_disclosure", full_disclosure_page: 999 }
    assert_response :success
    assert_select "#full_disclosure h2", text: /19 件/
    assert_select "#full_disclosure article", count: 19
    assert_select "#full_disclosure article a", text: hidden.title, count: 0
  end

  test "related CVE judgement remains visible inside its source block" do
    cve = ingest.cve
    cve.update!(current_judgement: "emergency")
    create_posts("full_disclosure", 1).first.update!(body: cve.identifier)
    get root_path
    assert_response :success
    assert_select "#cve h2", text: /CVE\s+1 件/
    assert_select "#emergency a", text: cve.identifier
    assert_select "#full_disclosure article", text: /関連CVE：.*Emergency（緊急）/m
    assert_select "#emergency article", count: 0
  end

  test "CVE subsection pagination still uses fifty records per page" do
    51.times do |i|
      cve = Cve.create!(identifier: "CVE-2026-#{(10000 + i)}", state: "PUBLISHED", date_published: 3.days.ago,
        match_status: "matched", current_judgement: "unknown")
      cve.product_matches.create!(product_name: "Ruby on Rails", rule: "vendor_product", matched_term: "rails", matched_text: "rails")
    end
    get root_path, params: { sources: "cve", unknown_page: 2 }
    assert_response :success
    assert_select "#cve h2", text: /51 件/
    assert_select "#unknown tbody tr", count: 1
    assert_select "#unknown nav a", text: "前へ"
    assert_select "#full_disclosure", count: 0
  end
end
