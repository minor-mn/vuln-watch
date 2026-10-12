class CveSnapshot < ApplicationRecord
  belongs_to :cve
  belongs_to :cvelist_sync, optional: true
  has_many :source_revisions, dependent: :restrict_with_exception

  validates :raw_json, :record_date_updated, presence: true
end
