require "test_helper"

class CveEvaluationTest < ActiveSupport::TestCase
  include ActionMailer::TestHelper

  V31_NETWORK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".freeze
  V31_LOW_PRIV = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".freeze

  setup do
    @mail_to = ENV["MAIL_TO"]
    ENV["MAIL_TO"] = "security@example.com, ops@example.com"
  end

  teardown { ENV["MAIL_TO"] = @mail_to }

  def evaluation(client)
    CveEvaluation.new(analyzer: CveAnalyzer.new(client:))
  end

  test "mails a matched emergency only once, even after it stops and starts being one" do
    client = FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" })
    cve = ingest(updated: "2026-10-01T00:00:00Z", cna_vectors: [ V31_NETWORK ]).cve

    assert_emails(1) { evaluation(client).call(cve) }
    mail = ActionMailer::Base.deliveries.last
    assert_equal [ "security@example.com", "ops@example.com" ], mail.to
    assert_match cve.identifier, mail.subject
    assert cve.reload.notification.sent_at

    assert_no_emails do
      ingest(updated: "2026-10-02T00:00:00Z", cna_updated: "2026-10-02T00:00:00Z", cna_vectors: [ V31_LOW_PRIV ])
      evaluation(client).call(cve, changed_sources: [ "cna" ])
      assert cve.reload.judged_non_emergency?

      ingest(updated: "2026-10-03T00:00:00Z", cna_updated: "2026-10-03T00:00:00Z", cna_vectors: [ V31_NETWORK ])
      evaluation(client).call(cve, changed_sources: [ "cna" ])
      assert cve.reload.judged_emergency?
    end
  end

  test "requests only analysis and leaves translations for the daily batch" do
    client = FakeOpenaiClient.new
    cve = ingest(vendor: "n/a", product: "n/a", description: "A flaw in Postgres.").cve
    evaluator = evaluation(client)

    evaluator.call(cve)
    assert_equal [ "cve_analysis" ], client.calls.map { |request| request.fetch(:schema_name) }
    assert_nil cve.product_matches.reload.sole.matched_text_ja

    evaluator.call(cve)
    assert_equal 1, client.calls.size
    assert_nil cve.product_matches.reload.sole.matched_text_ja
  end

  test "does not mail possible matches" do
    client = FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" })
    cve = ingest(vendor: "n/a", product: "n/a", description: "Postgres RCE.", cna_vectors: [ V31_NETWORK ]).cve

    assert_no_emails { evaluation(client).call(cve) }
    assert cve.reload.judged_emergency?
    assert_nil cve.notification
  end

  test "CVEs without matching products do not request analysis change judgement or send mail" do
    cve = ingest(vendor: "n/a", product: "n/a", description: "SQL injection using Postgres.").cve
    cve.latest_snapshot.update!(raw_json: cve_json(vendor: "acme", product: "widget", description: "SQL injection using Postgres."))
    matcher = ProductMatcher.new(sample_products)
    CveIngestor.new(matcher: matcher).ingest(CveRecord.new(cve.latest_snapshot.raw_json))
    client = FakeOpenaiClient.new(error: OpenaiClient::Error.new("Must not call the API"))

    assert_no_difference [ "AiAnalysis.count", "Judgement.count", "Notification.count" ] do
      assert_no_emails { evaluation(client).call(cve) }
    end
    assert_empty client.calls
    assert_empty cve.reload.product_matches
  end

  test "still judges with the previous analysis when OpenAI fails, then raises" do
    cve = ingest(updated: "2026-10-01T00:00:00Z", cna_vectors: [ V31_NETWORK ]).cve
    evaluation(FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" })).call(cve)

    ingest(updated: "2026-10-02T00:00:00Z", cna_updated: "2026-10-02T00:00:00Z", cna_vectors: [ V31_LOW_PRIV ])
    failing = FakeOpenaiClient.new(error: OpenaiClient::Error.new("boom"))

    assert_raises(OpenaiClient::Error) { evaluation(failing).call(cve, changed_sources: [ "cna" ]) }
    assert cve.reload.judged_non_emergency?
  end
end
