class Judgement < ApplicationRecord
  CONDITION_VALUES = { met: "met", not_met: "not_met", unknown: "unknown" }.freeze

  belongs_to :cve
  belongs_to :selected_assessment, class_name: "CvssAssessment", optional: true
  belongs_to :ai_analysis, optional: true
  has_one :notification, dependent: :restrict_with_exception

  enum :result, { emergency: "emergency", non_emergency: "non_emergency", unknown: "unknown" }, validate: true
  enum :attack_condition, CONDITION_VALUES, prefix: :attack, validate: true
  enum :capability_condition, CONDITION_VALUES, prefix: :capability, validate: true

  validates :effective_at, presence: true
end
