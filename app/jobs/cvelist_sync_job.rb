class CvelistSyncJob < ApplicationJob
  queue_as :default

  # Never run two syncs at once; a run that overlaps the next schedule is simply dropped.
  limits_concurrency to: 1, key: "cvelist_sync", on_conflict: :discard

  def perform(rescan: false)
    CvelistSynchronizer.new.call(rescan:).each do |result|
      job = rescan ? CveEvaluationJob.set(priority: 10) : CveEvaluationJob
      job.perform_later(result.cve, result.changed_sources)
    end
  end
end
