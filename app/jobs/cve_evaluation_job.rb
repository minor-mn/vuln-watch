class CveEvaluationJob < ApplicationJob
  queue_as :default

  # One evaluation per CVE at a time, so that judgements and the notification are not duplicated.
  limits_concurrency to: 1, key: ->(cve, *) { "cve_evaluation/#{cve.id}" }

  retry_on OpenaiClient::Error, wait: :polynomially_longer, attempts: 5

  def perform(cve, changed_sources = [])
    CveEvaluation.new.call(cve, changed_sources:)
  end
end
