class Cve < ApplicationRecord
  has_many :cve_snapshots, dependent: :destroy
  has_many :product_matches, dependent: :destroy
  has_many :source_revisions, dependent: :destroy
  has_many :ai_analyses, dependent: :destroy
  has_many :judgements, dependent: :destroy
  has_one :notification, dependent: :destroy

  enum :match_status, { matched: "matched", possible_match: "possible_match", unmatched: "unmatched" }, validate: true
  scope :published, -> { where(state: "PUBLISHED") }

  enum :current_judgement,
    { emergency: "emergency", non_emergency: "non_emergency", unknown: "unknown" },
    prefix: :judged, validate: true

  validates :identifier, presence: true, uniqueness: true
  validates :state, presence: true

  def to_param
    identifier
  end

  def latest_snapshot
    cve_snapshots.order(record_date_updated: :desc).first
  end

  def latest_judgement
    if judgements.loaded?
      judgements.max_by { |judgement| [ judgement.effective_at, judgement.id ] }
    else
      judgements.order(effective_at: :desc, id: :desc).first
    end
  end

  # The most recent earlier judgement result that differs from the current one, if any.
  def previous_judgement_result
    judgements.where.not(result: current_judgement).order(effective_at: :desc, id: :desc).pick(:result)
  end

  def latest_ai_analysis
    ai_analyses.order(:analyzed_at, :id).last
  end

  # Only affected-product identities confirm a match; description-only candidates stay possible.
  def refresh_match_status!
    matches = product_matches.reload
    status = if matches.empty? then "unmatched"
    elsif matches.any? { |match| !match.by_description? } then "matched"
    else "possible_match"
    end
    update!(match_status: status)
  end

  # The assessment used for condition 1: CNA before CISA, then the newest CVSS version.
  # dateUpdated is deliberately not considered.
  def selected_assessment
    CvssAssessment.preferred(current_assessments_by_source)
  end

  def analysis_eligible?
    state == "PUBLISHED" && selected_assessment&.remotely_exploitable_without_interaction? == true
  end

  # The newest revision of each source (cna / cisa_adp).
  def current_source_revisions
    source_revisions
      .select("DISTINCT ON (source) source_revisions.*")
      .order(:source, source_date_updated: :desc)
  end

  # { "cna" => [assessments], "cisa_adp" => [assessments] } from the current revisions.
  def current_assessments_by_source
    current_source_revisions.includes(:cvss_assessments).to_h do |revision|
      [ revision.source, revision.cvss_assessments.to_a ]
    end
  end

  # True when CNA and CISA disagree on AV, PR or whether UI is required.
  # UI letters differ between v3 (R) and v4 (P / A), so only "N or not" is compared.
  def assessment_mismatch?
    by_source = current_assessments_by_source
    by_source.fetch("cna", []).product(by_source.fetch("cisa_adp", [])).any? do |cna, cisa|
      cna.attack_vector != cisa.attack_vector ||
        cna.privileges_required != cisa.privileges_required ||
        (cna.user_interaction == "N") != (cisa.user_interaction == "N")
    end
  end
end
