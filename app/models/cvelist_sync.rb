class CvelistSync < ApplicationRecord
  has_many :cve_snapshots, dependent: :nullify

  enum :status, { running: "running", succeeded: "succeeded", failed: "failed" }, validate: true

  validates :started_at, presence: true

  def self.last_succeeded
    succeeded.order(finished_at: :desc).first
  end

  # The first sync also takes CVEs published this long before it (to check it works and to
  # cover vulnerabilities that are still fresh).
  INITIAL_LOOKBACK = 1.month

  # CVEs published before this are not stored.
  def self.watch_from
    first_started_at = succeeded.minimum(:started_at)
    first_started_at && first_started_at - INITIAL_LOOKBACK
  end
end
