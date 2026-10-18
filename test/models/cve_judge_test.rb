require "test_helper"

class CveJudgeTest < ActiveSupport::TestCase
  V40_NETWORK = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".freeze
  V31_NETWORK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".freeze
  V31_LOW_PRIV = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".freeze
  V31_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".freeze

  def analysis_for(cve, **capabilities)
    CveAnalyzer.new(client: FakeOpenaiClient.new(capabilities:)).analyze(cve)
  end

  def judge(cve, changed_sources: %w[cna cisa_adp], **capabilities)
    CveJudge.new(cve).judge(analysis: analysis_for(cve, **capabilities), changed_sources:)
  end

  test "emergency when reachable by anyone and RCE" do
    cve = ingest(cna_vectors: [ V31_NETWORK ]).cve

    assert judge(cve, remote_code_execution: "true").emergency?
    assert cve.reload.judged_emergency?
  end

  test "non_emergency when a privilege is required, even if capabilities are unknown" do
    ingest(updated: "2026-09-30T00:00:00Z")
    cve = ingest(cna_vectors: [ V31_LOW_PRIV ]).cve

    judgement = judge(cve, remote_code_execution: "unknown")

    assert judgement.non_emergency?
    assert judgement.attack_not_met?
  end

  test "non_emergency when no capability is gained" do
    assert judge(ingest(cna_vectors: [ V31_NETWORK ]).cve).non_emergency?
  end

  test "unknown when there is no assessment yet, never non_emergency" do
    ingest(updated: "2026-09-30T00:00:00Z")
    judgement = judge(ingest(cna_vectors: []).cve, remote_code_execution: "true")

    assert judgement.unknown?
    assert judgement.attack_unknown?
  end

  test "unknown when reachable but the capabilities cannot be told" do
    assert judge(ingest(cna_vectors: [ V31_NETWORK ]).cve, root_access: "unknown").unknown?
  end

  test "adopts CNA over CISA and the newest CVSS version" do
    cve = ingest(cna_vectors: [ V31_LOCAL, V40_NETWORK ], cisa_updated: "2026-10-05T00:00:00Z", cisa_vectors: [ V31_LOW_PRIV ]).cve

    judgement = judge(cve, remote_code_execution: "true")

    assert_equal [ "cna", "4.0" ], [ judgement.selected_assessment.source, judgement.selected_assessment.version ]
    assert judgement.emergency?
  end

  test "falls back to CISA when CNA has no assessment" do
    cve = ingest(cna_vectors: [], cisa_updated: "2026-10-05T00:00:00Z", cisa_vectors: [ V31_NETWORK ]).cve

    assert_equal "cisa_adp", judge(cve, remote_code_execution: "true").selected_assessment.source
  end

  test "records the history when the CNA assessment changes" do
    cve = ingest(updated: "2026-10-01T09:00:00Z", cna_vectors: [ V31_NETWORK ]).cve
    judge(cve, remote_code_execution: "true")

    result = ingest(updated: "2026-10-03T12:00:00Z", cna_updated: "2026-10-03T12:00:00Z", cna_vectors: [ V31_LOW_PRIV ])
    judgement = judge(cve.reload, changed_sources: result.changed_sources, remote_code_execution: "true")

    assert judgement.non_emergency?
    assert_equal Time.utc(2026, 10, 3, 12), judgement.effective_at
    assert_includes judgement.changes_summary,
      { "type" => "assessment", "source" => "cna", "version" => "3.1", "field" => "PR", "from" => "N", "to" => "L" }
    assert_includes judgement.changes_summary, { "type" => "result", "from" => "emergency", "to" => "non_emergency" }
    assert_equal "emergency", cve.reload.previous_judgement_result
    assert_equal 2, cve.judgements.count
  end

  test "records the CISA dateUpdated when only CISA changed" do
    ingest(updated: "2026-09-30T00:00:00Z")
    cve = ingest(updated: "2026-10-01T09:00:00Z", cna_vectors: []).cve
    judge(cve, remote_code_execution: "true")

    result = ingest(updated: "2026-10-01T12:00:00Z", cna_updated: "2026-10-01T09:00:00Z", cna_vectors: [],
      cisa_updated: "2026-10-01T12:00:00Z", cisa_vectors: [ V31_NETWORK ])
    judgement = judge(cve.reload, changed_sources: result.changed_sources, remote_code_execution: "true")

    assert judgement.emergency?
    assert_equal Time.utc(2026, 10, 1, 12), judgement.effective_at
  end

  test "does not record a judgement when nothing changed" do
    cve = ingest(cna_vectors: [ V31_NETWORK ]).cve
    first = judge(cve, remote_code_execution: "true")

    assert_equal first, judge(cve, remote_code_execution: "true")
    assert_equal 1, cve.judgements.count
  end
end
