namespace :cvelist do
  desc "Fetch CVEProject/cvelistV5, ingest CVEs matching monitored products and evaluate them"
  task sync: :environment do
    logger = Logger.new($stdout)
    results = CvelistSynchronizer.new(logger:).call
    puts "Stored #{results.size} CVE(s)"

    evaluation = CveEvaluation.new(analyzer: CveAnalyzer.new(logger:), notifier: EmergencyNotifier.new(logger:))
    results.each do |result|
      evaluation.call(result.cve, changed_sources: result.changed_sources)
    rescue OpenaiClient::Error => error
      logger.error("[evaluation] #{result.cve.identifier}: #{error.message}")
    end
  end
end

namespace :cves do
  desc "Re-evaluate every stored CVE (OpenAI is called only for CVEs whose AI input changed)"
  task evaluate: :environment do
    logger = Logger.new($stdout)
    evaluation = CveEvaluation.new(analyzer: CveAnalyzer.new(logger:), notifier: EmergencyNotifier.new(logger:))
    Cve.find_each do |cve|
      evaluation.call(cve)
    rescue OpenaiClient::Error => error
      logger.error("[evaluation] #{cve.identifier}: #{error.message}")
    end
  end
end
