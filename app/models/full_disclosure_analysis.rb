require "digest"

class FullDisclosureAnalysis < ApplicationRecord
  METRICS = {
    "AV" => { field: "attack_vector", values: %w[N A L P unknown] },
    "PR" => { field: "privileges_required", values: %w[N L H unknown] },
    "UI" => { field: "user_interaction", values: %w[N R unknown] }
  }.freeze

  belongs_to :information_item
  validates :input_hash, :title, :original_body, :body_ja, :model, :prompt_version, :analyzed_at, presence: true
  validates :input_hash, uniqueness: { scope: :information_item_id }
  validate :valid_assessments

  def self.input_hash(item)
    Digest::SHA256.hexdigest(JSON.generate([ item.title, item.full_body ]))
  end

  private
    def valid_assessments
      valid = assessments.is_a?(Array) && assessments.any? && assessments.all? do |assessment|
        assessment.is_a?(Hash) && assessment["subject"].is_a?(String) && assessment["subject"].present? &&
          METRICS.values.all? { |metric| metric[:values].include?(assessment[metric[:field]]) } &&
          assessment["evidence"].is_a?(Hash) && METRICS.keys.all? do |metric|
            evidence = assessment["evidence"][metric]
            evidence.is_a?(Hash) && evidence["quote"].is_a?(String) && evidence["explanation"].is_a?(String)
          end
      end
      errors.add(:assessments, "is invalid") unless valid
    end
end
