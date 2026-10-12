# The one-time emergency email. At most one row per CVE.
class CreateNotifications < ActiveRecord::Migration[8.0]
  def change
    create_table :notifications do |t|
      t.references :cve, null: false, foreign_key: true, index: { unique: true }
      t.references :judgement, null: false, foreign_key: true
      t.datetime :sent_at

      t.timestamps
    end
  end
end
