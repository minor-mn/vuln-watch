require "test_helper"

class FullDisclosuresControllerTest < ActionDispatch::IntegrationTest
  setup do
    @post = InformationItem.create!(source: "full_disclosure", title: "Security report", url: "https://seclists.org/fulldisclosure/2026/Oct/1",
      body: "RSS excerpt", full_body: "Full original body <script>alert(1)</script>", published_at: 1.day.ago,
      fetched_at: Time.current, relevant: true, details: { "kind" => "mailing_list" })
  end

  def create_analysis
    evidence = %w[AV PR UI].to_h { |metric| [ metric, { "quote" => "", "explanation" => "原文から判断できません。" } ] }
    @post.full_disclosure_analyses.create!(input_hash: FullDisclosureAnalysis.input_hash(@post), title: @post.title,
      original_body: @post.full_body, body_ja: "本文全体の和訳です。\n第2段落です。<script>alert(2)</script>", model: "test-model",
      prompt_version: FullDisclosureAnalyzer::PROMPT_VERSION, analyzed_at: Time.current,
      assessments: [ { "subject" => "Security report", "attack_vector" => "unknown", "privileges_required" => "unknown", "user_interaction" => "unknown", "evidence" => evidence } ])
  end

  test "index links Full Disclosure to a local detail and orders it before GitHub" do
    get root_path
    assert_response :success
    assert_select "#full_disclosure article h3 a[href=?]", full_disclosure_path(@post), text: @post.title
    headings = css_select("main > div > section").map { |section| section["id"] }
    assert_equal %w[cve full_disclosure github_advisory slashdot], headings
    assert_select "#full_disclosure article h3 a[target]", count: 0
  end

  test "detail shows saved metrics full translation and original as escaped text" do
    create_analysis
    get full_disclosure_path(@post)
    assert_response :success
    assert_select "h1", text: @post.title
    assert_match "AV / PR / UI", response.body
    assert_match "不明", response.body
    assert_match "第2段落です。", response.body
    assert_match "Full original body", response.body
    assert_not_includes response.body, "<script>alert(1)</script>"
    assert_not_includes response.body, "<script>alert(2)</script>"
    assert_select "a[href=?]", @post.url, text: "配信元の原文"
  end

  test "detail is read only before analysis and other sources cannot use this route" do
    assert_no_difference "FullDisclosureAnalysis.count" do
      assert_no_enqueued_jobs do
        get full_disclosure_path(@post)
      end
    end
    assert_response :success
    assert_match "まだ完了していません", response.body
    @post.update!(source: "github_advisory")
    get full_disclosure_path(@post)
    assert_response :not_found
  end

  test "detail never renders an unsafe source URL" do
    @post.update!(url: "javascript:alert(1)")
    get full_disclosure_path(@post)
    assert_response :success
    assert_select "a[href^='javascript:']", count: 0
    assert_select "a", text: "配信元の原文", count: 0
  end
end
