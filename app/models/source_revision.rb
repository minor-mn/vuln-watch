class SourceRevision < ApplicationRecord
  belongs_to :cve
  belongs_to :cve_snapshot
  has_many :cvss_assessments, dependent: :destroy

  enum :source, { cna: "cna", cisa_adp: "cisa_adp" }, validate: true

  validates :source_date_updated, presence: true
end
