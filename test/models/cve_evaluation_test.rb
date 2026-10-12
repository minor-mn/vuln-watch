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
    CveEvaluation.new(analyzer: CveAnalyzer.new(client:), translator: MatchedTextTranslator.new(client:))
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

  test "does not mail possible matches" do
    client = FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" },
      product_assessments: [ { "product_name" => "PostgreSQL", "affected" => "unknown" } ])
    cve = ingest(vendor: "acme", product: "widget", description: "Postgres RCE.", cna_vectors: [ V31_NETWORK ]).cve

    assert_no_emails { evaluation(client).call(cve) }
    assert cve.reload.judged_emergency?
    assert_nil cve.notification
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
