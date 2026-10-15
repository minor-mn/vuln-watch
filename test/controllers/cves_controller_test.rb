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
    assert_select "#unknown", text: /説明文のみで一致/
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

  test "CVEs without matching products leave the list but retain their original record" do
    @possible.product_matches.delete_all
    @possible.refresh_match_status!

    get root_path
    assert_response :success
    assert_select "a", text: @possible.identifier, count: 0

    get cve_path(@possible)
    assert_response :success
    assert_match "現在一致する監視対象製品はありません", response.body
    assert_equal "Uses Postgres.", @possible.latest_snapshot.raw_json.dig("containers", "cna", "descriptions", 0, "value")
  end

  test "removing an incorrect PostgreSQL match leaves the Rails match in the list" do
    @cve.product_matches.create!(product_name: "PostgreSQL", rule: "description", matched_term: "postgres", matched_text: "Postgres")
    matcher = ProductMatcher.new(sample_products)
    CveIngestor.new(matcher: matcher).ingest(CveRecord.new(@cve.latest_snapshot.raw_json))

    get root_path
    assert_response :success
    assert_select "tr", text: /#{@cve.identifier}/ do
      assert_select "td", text: /Ruby on Rails/
      assert_select "td", text: /PostgreSQL/, count: 0
    end
  end
end
