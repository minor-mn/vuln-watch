class CvssAssessment < ApplicationRecord
  VERSIONS = %w[4.0 3.1 3.0].freeze # newest first

  belongs_to :source_revision
  has_one :cve, through: :source_revision

  validates :version, inclusion: { in: VERSIONS }
  validates :attack_vector, :privileges_required, :user_interaction, :vector_string, presence: true

  delegate :source, to: :source_revision

  def self.preferred(by_source)
    %w[cna cisa_adp].each do |source|
      found = by_source.fetch(source, []).min_by { |assessment| VERSIONS.index(assessment.version) }
      return found if found
    end
    nil
  end

  # Condition 1: reachable over the network, no privileges, no user interaction.
  def remotely_exploitable_without_interaction?
    attack_vector == "N" && privileges_required == "N" && user_interaction == "N"
  end
end
