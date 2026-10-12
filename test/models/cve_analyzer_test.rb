require "test_helper"

class CveAnalyzerTest < ActiveSupport::TestCase
  V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".freeze

  test "stores the analysis and reuses it while the AI input is unchanged" do
    client = FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" })
    analyzer = CveAnalyzer.new(client:)
    cve = ingest(updated: "2026-10-01T00:00:00Z", cna_vectors: [ V31 ]).cve

    analysis = analyzer.analyze(cve)
    assert_equal "true", analysis.remote_code_execution
    assert_equal "概要", analysis.summary_overview
    assert_equal AiInput.for(cve).digest, analysis.input_hash
    assert_equal CveAnalyzer::PROMPT_VERSION, analysis.prompt_version

    # Only the record's dateUpdated changed: no new call.
    ingest(updated: "2026-10-02T00:00:00Z", cna_updated: "2026-10-01T00:00:00Z", cna_vectors: [ V31 ])
    assert_equal analysis, analyzer.analyze(cve)
    assert_equal 1, client.calls.size

    # A CISA assessment was added: the input changed.
    ingest(updated: "2026-10-03T00:00:00Z", cna_updated: "2026-10-01T00:00:00Z", cna_vectors: [ V31 ],
      cisa_updated: "2026-10-03T00:00:00Z", cisa_vectors: [ V31 ])
    assert_not_equal analysis, analyzer.analyze(cve)
    assert_equal 2, client.calls.size
  end

  test "does nothing when OpenAI is not configured" do
    client = FakeOpenaiClient.new(configured: false)
    cve = ingest.cve

    assert_nil CveAnalyzer.new(client:, logger: Logger.new(nil)).analyze(cve)
    assert_empty client.calls
  end

  test "promotes a possible match the AI confirms" do
    client = FakeOpenaiClient.new(product_assessments: [ { "product_name" => "PostgreSQL", "affected" => "true" } ])
    cve = ingest(vendor: "acme", product: "widget", description: "A flaw in Postgres.").cve

    CveAnalyzer.new(client:).analyze(cve)

    assert cve.reload.matched?
    assert cve.product_matches.sole.ai_affects_yes?
  end

  test "keeps a possible match the AI rejects" do
    client = FakeOpenaiClient.new(product_assessments: [ { "product_name" => "PostgreSQL", "affected" => "false" } ])
    cve = ingest(vendor: "acme", product: "widget", description: "Widget talks to Postgres.").cve

    CveAnalyzer.new(client:).analyze(cve)

    assert cve.reload.possible_match?
    assert cve.product_matches.sole.ai_affects_no?
  end
end
