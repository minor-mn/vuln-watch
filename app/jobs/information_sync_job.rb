class InformationSyncJob < ApplicationJob
  queue_as :default

  def perform
    InformationSources.enabled.each { |source| InformationSourceSyncJob.perform_later(source) }
  end
end
