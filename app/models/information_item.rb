class InformationItem < ApplicationRecord
  validates :source, inclusion: { in: InformationSources::LABELS.keys - [ "cve" ] }
  validates :url, :title, :published_at, :fetched_at, presence: true

  # Keep every collected row. This selection is applied separately for each source,
  # before relevance/reply filtering, so no arbitrary topic count limit is introduced.
  def self.selected(source, now: Time.current)
    scope = where(source:, listed: true).where(published_at: ..now).order(published_at: :desc, id: :desc)
    recent = scope.where(published_at: (now - 24.hours)..now)
    recent.count >= 5 ? recent : scope.limit(5)
  end

  def reply?
    details["kind"] == "mailing_list_reply"
  end

  def cve_identifiers
    ([ details["cve_id"] ] + "#{title} #{body}".scan(/\bCVE-\d{4}-\d{4,}\b/i)).compact.map(&:upcase).uniq
  end

  def section(cves = {})
    return "topics" if source == "slashdot"
    results = cve_identifiers.filter_map { |id| cves[id]&.current_judgement }
    %w[emergency non_emergency unknown].find { |result| results.include?(result) } || "unknown"
  end
end
