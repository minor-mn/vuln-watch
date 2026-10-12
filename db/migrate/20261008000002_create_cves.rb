# A CVE that matched a monitored product. Holds the current state;
# history lives in cve_snapshots, source_revisions and judgements.
class CreateCves < ActiveRecord::Migration[8.0]
  def change
    create_table :cves do |t|
      t.string :identifier, null: false              # e.g. CVE-2026-12345
      t.string :state, null: false                   # cveMetadata.state (PUBLISHED / REJECTED)
      t.datetime :date_published                     # cveMetadata.datePublished
      t.datetime :record_date_updated                # cveMetadata.dateUpdated (re-fetch trigger only)

      t.string :match_status, null: false            # matched / possible_match
      t.string :current_judgement, null: false, default: "unknown" # emergency / non_emergency / unknown
      t.boolean :assessment_mismatch, null: false, default: false # CNA and CISA disagree on AV/PR/UI

      t.timestamps
    end
    add_index :cves, :identifier, unique: true
    add_index :cves, :current_judgement
    add_index :cves, :match_status
    add_index :cves, :date_published
  end
end
