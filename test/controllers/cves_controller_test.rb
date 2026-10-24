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

  test "lists the stored mismatch result and removes the badge after assessments agree" do
    options = {
      id: "CVE-2026-8124", cna_vectors: [ V31_NETWORK ],
      cna_updated: "2026-10-01T00:00:00Z",
      cisa_updated: "2026-10-02T00:00:00Z",
      cisa_vectors: [ V31_NETWORK.sub("PR:N", "PR:L") ]
    }
    cve = ingest(**options).cve
    assert cve.assessment_mismatch

    get root_path
    assert_response :success
    assert_select "tr", text: /#{cve.identifier}/ do
      assert_select "span", text: "評価不一致", count: 1
    end
    assert_select "tr", text: /#{@cve.identifier}/ do
      assert_select "span", text: "評価不一致", count: 0
    end

    ingest(**options.merge(updated: "2026-10-03T00:00:00Z",
      cisa_updated: "2026-10-03T00:00:00Z", cisa_vectors: [ V31_NETWORK ]))
    refute cve.reload.assessment_mismatch

    get root_path
    assert_response :success
    assert_select "tr", text: /#{cve.identifier}/ do
      assert_select "span", text: "評価不一致", count: 0
    end
  end

  test "listing more CVEs does not add assessment queries" do
    # Warm up schema and rendering before measuring database queries.
    get root_path
    before = listing_assessment_queries

    6.times do |index|
      ingest(id: "CVE-2026-#{8200 + index}",
        cisa_updated: "2026-10-02T00:00:00Z", cisa_vectors: [ V31_NETWORK ])
    end

    after = listing_assessment_queries
    assert_equal before.size, after.size, after.join("\n")
    assert_operator after.size, :<=, 2, after.join("\n")
  end

  private
    def listing_assessment_queries
      queries = []
      subscriber = ->(_name, _start, _finish, _id, payload) do
        sql = payload[:sql]
        queries << sql if sql.match?(/\bFROM "(?:source_revisions|cvss_assessments)"/i)
      end
      ActiveSupport::Notifications.subscribed(subscriber, "sql.active_record") do
        ActiveRecord::Base.uncached { get root_path }
      end
      assert_response :success
      queries
    end
end
