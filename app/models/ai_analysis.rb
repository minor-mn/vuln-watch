class AiAnalysis < ApplicationRecord
  CAPABILITIES = %i[remote_code_execution authentication_bypass shell_access root_access].freeze
  TRI_STATE = %w[true false unknown].freeze

  belongs_to :cve

  validates :input_hash, :input, :model, :prompt_version, :analyzed_at, presence: true
  CAPABILITIES.each do |capability|
    validates capability, inclusion: { in: TRI_STATE }
  end

  def capability_values
    CAPABILITIES.index_with { |capability| public_send(capability) }
  end
end
