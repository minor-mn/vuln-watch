namespace :information do
  desc "Enqueue a refresh of all enabled information sources"
  task refresh: :environment do
    InformationSyncJob.perform_now
  end
end
