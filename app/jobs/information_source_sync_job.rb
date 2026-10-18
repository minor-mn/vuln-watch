class InformationSourceSyncJob < ApplicationJob
  queue_as :default
  limits_concurrency to: 1, key: ->(source) { "information:#{source}" }, duration: 1.hour, on_conflict: :discard

  def perform(source)
    return unless InformationSources.enabled.include?(source)
    state = InformationSourceState.find_or_create_by!(source:)
    return if state.retry_at&.future?
    state.update!(attempted_at: Time.current)
    synchronize(source)
    state.update!(succeeded_at: Time.current, error_message: nil, retry_at: nil)
  rescue InformationHttp::Error => error
    state&.update!(error_message: error.message, retry_at: error.retry_at)
    raise
  rescue => error
    state&.update!(error_message: "#{error.class}: #{error.message}".truncate(500))
    raise
  end

  private
    def synchronize(source)
      if source == "cve"
        CvelistSyncJob.perform_now
      else
        InformationCollector.new.call(source)
      end
    end
end
