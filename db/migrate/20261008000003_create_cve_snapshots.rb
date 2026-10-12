# The CVE JSON exactly as fetched, one row per record version.
class CreateCveSnapshots < ActiveRecord::Migration[8.0]
  def change
    create_table :cve_snapshots do |t|
      t.references :cve, null: false, foreign_key: true
      t.references :cvelist_sync, foreign_key: true
      t.jsonb :raw_json, null: false
      t.datetime :record_date_updated, null: false   # cveMetadata.dateUpdated of this version
      t.string :git_commit                           # cvelistV5 commit the file was read from

      t.timestamps
    end
    add_index :cve_snapshots, [ :cve_id, :record_date_updated ], unique: true
  end
end
