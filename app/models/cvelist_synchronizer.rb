# Follows CVEProject/cvelistV5 with git.
#
# The first run fetches only the last month of history and ingests CVEs published in that month.
# Later runs read the CVE files changed since the last successful sync and ingest those that
# match a monitored product (or are already stored). Older CVEs are never stored.
class CvelistSynchronizer
  def initialize(repository: Cvelist::Repository.new, matcher: ProductMatcher.new, logger: Rails.logger)
    @repository = repository
    @matcher = matcher
    @logger = logger
  end

  def call
    from_commit = CvelistSync.last_succeeded&.to_commit
    sync = CvelistSync.create!(status: "running", from_commit:, started_at: Time.current)
    watch_from = CvelistSync.watch_from || sync.started_at - CvelistSync::INITIAL_LOOKBACK

    if from_commit
      prepare_repository
      @repository.ensure_commit!(from_commit)
    else
      # Changes made in the oldest fetched commit itself are not in the diff; a day of margin
      # keeps that commit before watch_from.
      prepare_repository(since: watch_from - 1.day)
      from_commit = @repository.oldest_commit
    end
    to_commit = @repository.remote_head

    files = @repository.changed_cve_files(from_commit, to_commit)
    @repository.prefetch!(to_commit, files)
    failures = []
    results = ingest_files(files, watch_from:, sync:, commit: to_commit, failures:)

    sync.update!(
      status: "succeeded",
      to_commit:,
      changed_files_count: files.size,
      matched_cves_count: results.size,
      error_message: failures.presence&.join("\n"),
      finished_at: Time.current
    )
    results
  rescue => error
    sync&.update!(status: "failed", error_message: "#{error.class}: #{error.message}", finished_at: Time.current)
    raise
  end

  private
    def prepare_repository(since: nil)
      if @repository.cloned?
        @repository.fetch!(since:)
      else
        @repository.clone!(since:)
      end
    end

    def ingest_files(files, watch_from:, sync:, commit:, failures:)
      ingestor = CveIngestor.new(matcher: @matcher, published_after: watch_from, sync:, commit:)
      stored = Cve.pluck(:identifier).to_set

      files.filter_map do |file|
        raw = @repository.read(commit, file)
        next unless stored.include?(File.basename(file, ".json")) || @matcher.candidate?(raw)

        ingestor.ingest(CveRecord.parse(raw))
      rescue => error
        @logger.error("[cvelist] #{file}: #{error.class}: #{error.message}")
        failures << "#{file}: #{error.class}: #{error.message}"
        nil
      end
    end
end
