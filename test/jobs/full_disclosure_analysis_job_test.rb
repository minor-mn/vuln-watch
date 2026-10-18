require "test_helper"

class FullDisclosureAnalysisJobTest < ActiveJob::TestCase
  test "collection saves the full original separately from replies and enqueues analysis only when missing" do
    feeds = Object.new
    now = Time.current
    rows = [ { url: "https://seclists.org/fulldisclosure/2026/Oct/1", title: "Report", body: "RSS excerpt",
      published_at: now, details: { "kind" => "mailing_list" } } ]
    feeds.define_singleton_method(:fetch) { |*, **| rows }
    summarizer = Object.new
    summarizer.define_singleton_method(:call) { |*| }
    threads = Object.new
    threads.define_singleton_method(:fetch) do |item|
      { "url" => item.url, "status" => "empty", "comments" => [], "original_body" => "Complete original body\nSecond paragraph" }
    end
    collector = InformationCollector.new(feeds:, summarizer:, threads:)
    assert_enqueued_jobs 1, only: FullDisclosureAnalysisJob do
      collector.call("full_disclosure", now:)
    end
    item = InformationItem.find_by!(url: rows.first[:url])
    assert_equal "Complete original body\nSecond paragraph", item.full_body
    assert item.full_body_fetched_at
    assert_not item.thread.key?("original_body")
    assert_equal "RSS excerpt", item.body

    evidence = %w[AV PR UI].to_h { |metric| [ metric, { "quote" => "", "explanation" => "記載なし" } ] }
    item.full_disclosure_analyses.create!(input_hash: FullDisclosureAnalysis.input_hash(item), title: item.title,
      original_body: item.full_body, body_ja: "全文の和訳", model: "test", prompt_version: "test", analyzed_at: now,
      assessments: [ { "subject" => "Report", "attack_vector" => "unknown", "privileges_required" => "unknown", "user_interaction" => "unknown", "evidence" => evidence } ])
    assert_no_enqueued_jobs { collector.call("full_disclosure", now:) }
  end
end
