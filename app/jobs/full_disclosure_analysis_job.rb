class FullDisclosureAnalysisJob < ApplicationJob
  queue_as :default
  limits_concurrency to: 1, key: ->(item) { "full_disclosure_analysis/#{item.id}" }, duration: 15.minutes, on_conflict: :discard
  retry_on OpenaiClient::Error, wait: :polynomially_longer, attempts: 5

  def perform(item)
    FullDisclosureAnalyzer.new.analyze(item)
  end
end
