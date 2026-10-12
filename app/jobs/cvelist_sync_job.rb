class CvelistSyncJob < ApplicationJob
  queue_as :default

  # Never run two syncs at once; a run that overlaps the next schedule is simply dropped.
  limits_concurrency to: 1, key: "cvelist_sync", on_conflict: :discard

  def perform
    CvelistSynchronizer.new.call.each do |result|
      CveEvaluationJob.perform_later(result.cve, result.changed_sources)
    end
  end
end
