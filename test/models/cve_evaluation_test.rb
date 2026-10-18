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

  test "does not mail possible matches" do
    client = FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" })
    cve = ingest(vendor: "n/a", product: "n/a", description: "Postgres RCE.", cna_vectors: [ V31_NETWORK ]).cve

    assert_no_emails { evaluation(client).call(cve) }
    assert cve.reload.judged_emergency?
    assert_nil cve.notification
  end

  test "unmatched CVEs are analyzed and judged without sending mail" do
    cve = ingest(vendor: "acme", product: "widget").cve
    client = FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" })
    assert_no_emails { evaluation(client).call(cve) }
    assert cve.reload.judged_emergency?
    assert cve.unmatched?
    assert_equal 1, cve.ai_analyses.count
    assert_nil cve.notification
    assert_no_emails { evaluation(client).call(cve) }
    assert_equal 1, client.calls.size
  end

  test "non-emergency and unknown capabilities remain saved for unmatched CVEs" do
    { "false" => "non_emergency", "unknown" => "unknown" }.each_with_index do |(capability, expected), index|
      cve = ingest(id: "CVE-2026-999#{index}", vendor: "acme", product: "widget").cve
      client = FakeOpenaiClient.new(capabilities: { remote_code_execution: capability })
      assert_no_emails { evaluation(client).call(cve) }
      assert_equal expected, cve.reload.current_judgement
      assert_equal "概要", cve.latest_ai_analysis.summary_overview
    end
  end

  test "changed attack conditions update the judgement without another analysis" do
    cve = ingest(cna_vectors: [ V31_NETWORK ]).cve
    client = FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" })
    evaluation(client).call(cve)
    ingest(updated: "2026-10-02T00:00:00Z", cna_vectors: [ V31_LOW_PRIV ])
    assert_no_emails { evaluation(client).call(cve) }
    assert cve.reload.judged_non_emergency?
    assert_equal 1, client.calls.size
    assert_equal 1, cve.ai_analyses.count
  end

  test "missing product matches and rejected states never mail even if marked matched" do
    cve = ingest(vendor: "acme", product: "widget").cve
    cve.update!(match_status: "matched", current_judgement: "emergency")
    assert_no_emails { EmergencyNotifier.new.notify(cve) }
    assert_nil cve.notification
    cve.product_matches.create!(product_name: "Ruby on Rails", rule: "vendor_product", matched_term: "rails", matched_text: "rails")
    cve.update!(state: "REJECTED")
    assert_no_emails { EmergencyNotifier.new.notify(cve) }
    assert_nil cve.notification
  end

  test "still judges with the previous analysis when OpenAI fails, then raises" do
    cve = ingest(updated: "2026-10-01T00:00:00Z", cna_vectors: [ V31_NETWORK ]).cve
    evaluation(FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" })).call(cve)

    ingest(updated: "2026-10-02T00:00:00Z", description: "Changed RCE details", cna_vectors: [ V31_NETWORK ])
    failing = FakeOpenaiClient.new(error: OpenaiClient::Error.new("boom"))

    assert_raises(OpenaiClient::Error) { evaluation(failing).call(cve, changed_sources: [ "cna" ]) }
    assert cve.reload.judged_emergency?
  end
end
