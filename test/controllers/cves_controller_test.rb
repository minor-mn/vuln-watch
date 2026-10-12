require "test_helper"

class CvesControllerTest < ActionDispatch::IntegrationTest
  V31_NETWORK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".freeze

  setup do
    @cve = ingest(cna_vectors: [ V31_NETWORK ]).cve
    CveEvaluation.new(analyzer: CveAnalyzer.new(client: FakeOpenaiClient.new(capabilities: { remote_code_execution: "true" })),
      notifier: EmergencyNotifier.new(logger: Logger.new(nil))).call(@cve)
    @possible = ingest(id: "CVE-2026-0002", vendor: "acme", product: "widget", description: "Uses Postgres.").cve
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
end
