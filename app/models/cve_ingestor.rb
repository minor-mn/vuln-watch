# Stores one CVE record: the raw snapshot, product matches and, for each source
# (CNA / CISA-ADP) whose own dateUpdated changed, a new source revision with its assessments.
class CveIngestor
  Result = Data.define(:cve, :changed_sources)

  # published_after: new CVEs published before this time are not stored (past vulnerabilities).
  def initialize(matcher:, published_after: nil, sync: nil, commit: nil)
    @matcher = matcher
    @published_after = published_after
    @sync = sync
    @commit = commit
  end

  # Returns a Result, or nil when the record is not stored.
  def ingest(record)
    cve = Cve.find_by(identifier: record.identifier)
    matches = @matcher.match(record)
    return if cve.nil? && skip_new?(record, matches)

    Cve.transaction do
      cve ||= Cve.new(identifier: record.identifier)
      cve.lock! if cve.persisted?
      cve.assign_attributes(
        state: record.state,
        date_published: record.date_published,
        record_date_updated: record.record_date_updated
      )
      cve.match_status ||= "possible_match"
      cve.save!

      store_matches(cve, matches)
      cve.refresh_match_status!

      snapshot = store_snapshot(cve, record)
      changed_sources = store_source_revisions(cve, snapshot, record)
      cve.update!(assessment_mismatch: cve.assessment_mismatch?) if changed_sources.any?

      Result.new(cve:, changed_sources:)
    end
  end

  private
    def skip_new?(record, matches)
      return true if matches.empty?

      @published_after.present? && record.date_published.present? && record.date_published < @published_after
    end

    # Keep matching products; remove stale product matches without deleting the CVE.
    def store_matches(cve, matches)
      matched_ids = []
      matches.each do |match|
        product_match = cve.product_matches.find_or_initialize_by(product_name: match.product_name, rule: match.rule)
        product_match.update!(matched_term: match.matched_term, matched_text: match.matched_text)
        matched_ids << product_match.id
      end

      cve.product_matches.where(product_name: @matcher.product_names).where.not(id: matched_ids).delete_all
    end

    def store_snapshot(cve, record)
      cve.cve_snapshots.find_or_create_by!(record_date_updated: record.record_date_updated) do |snapshot|
        snapshot.raw_json = record.json
        snapshot.cvelist_sync = @sync
        snapshot.git_commit = @commit
      end
    end

    # Returns the sources whose container changed since the last stored revision.
    def store_source_revisions(cve, snapshot, record)
      record.source_containers.filter_map do |source, container|
        date_updated = record.source_date_updated(container) || record.record_date_updated
        next if cve.source_revisions.exists?(source:, source_date_updated: date_updated)

        revision = cve.source_revisions.create!(cve_snapshot: snapshot, source:, source_date_updated: date_updated)
        record.assessments(container).each do |assessment|
          revision.cvss_assessments.create!(assessment.to_h)
        end
        source
      end
    end
end
