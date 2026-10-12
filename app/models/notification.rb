class Notification < ApplicationRecord
  belongs_to :cve
  belongs_to :judgement

  validates :cve_id, uniqueness: true
end
