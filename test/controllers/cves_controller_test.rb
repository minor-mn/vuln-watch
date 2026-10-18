require "test_helper"

class CvesControllerTest < ActionDispatch::IntegrationTest
  V31_NETWORK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".freeze

  setup do
    @cve = ingest(cna_vectors: [ V31_NETWORK ]).cve
    client = FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" })
    CveEvaluation.new(analyzer: CveAnalyzer.new(client:), notifier: EmergencyNotifier.new(logger: Logger.new(nil))).call(@cve)
    @possible = ingest(id: "CVE-2026-0002", vendor: "n/a", product: "n/a", description: "Uses Postgres.").cve
  end

  test "lists CVEs in the three sections" do
    get root_path

    assert_response :success
    assert_select "#emergency a", text: @cve.identifier
    assert_select "#unknown a", text: @possible.identifier
    assert_select "#unknown", text: /メール対象候補（説明文のみ）/
  end

  test "shows the judgement, summary and history" do
    get cve_path(@cve)

    assert_response :success
    assert_select "h1", text: @cve.identifier
    assert_match "AV:N / PR:N / UI:N", response.body
    assert_match "概要", response.body
    assert_match "Emergency（緊急） と判定した", response.body
  end

  test "shows a CVE not judged yet" do
    get cve_path(@possible)

    assert_response :success
    assert_match "まだ判定していません", response.body
  end

  test "CVEs without matching products stay listed and retain their original record" do
    @possible.product_matches.delete_all
    @possible.refresh_match_status!

    get root_path
    assert_response :success
    assert_select "#unknown a", text: @possible.identifier

    get cve_path(@possible)
    assert_response :success
    assert_select "h2", text: "メール通知対象製品との一致", count: 0
    assert_equal "Uses Postgres.", @possible.latest_snapshot.raw_json.dig("containers", "cna", "descriptions", 0, "value")
  end

  test "removing an incorrect PostgreSQL match leaves the Rails match in the list" do
    @cve.product_matches.create!(product_name: "PostgreSQL", rule: "description", matched_term: "postgres", matched_text: "Postgres")
    matcher = ProductMatcher.new(sample_products)
    CveIngestor.new(matcher: matcher).ingest(CveRecord.new(@cve.latest_snapshot.raw_json))

    get root_path
    assert_response :success
    assert_select "tr", text: /#{@cve.identifier}/ do
      assert_select "td", text: /rails/
      assert_select "td", text: /PostgreSQL/, count: 0
    end
  end
  test "unmatched CVEs appear with original affected products and in the briefing API" do
    cve = ingest(id: "CVE-2026-8123", vendor: "acme", product: "Widget Server").cve
    client = FakeOpenaiClient.new
    CveEvaluation.new(analyzer: CveAnalyzer.new(client:)).call(cve)
    get root_path
    assert_response :success
    assert_select "#non_emergency tr", text: /#{cve.identifier}/ do
      assert_select "td", text: /Widget Server/
    end
    get "/api/briefing", params: { sources: "cve", hours: 1000 }
    row = response.parsed_body.dig("news", "items").find { |item| item.dig("advisory", "cve_id") == cve.identifier }
    assert row
    assert_includes row.dig("source", "title"), "Widget Server"
    assert_includes row["article_summary"], "概要"
    cve.update!(state: "REJECTED")
    get root_path
    assert_select "a", text: cve.identifier, count: 0
    get "/api/briefing", params: { sources: "cve", hours: 1000 }
    refute response.parsed_body.dig("news", "items").any? { |item| item.dig("advisory", "cve_id") == cve.identifier }
  end
end
