class InformationSourceState < ApplicationRecord
  validates :source, inclusion: { in: InformationSources::LABELS.keys }, uniqueness: true
end
