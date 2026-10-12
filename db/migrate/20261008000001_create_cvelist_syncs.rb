# One run of following CVEProject/cvelistV5 with git fetch + diff.
class CreateCvelistSyncs < ActiveRecord::Migration[8.0]
  def change
    create_table :cvelist_syncs do |t|
      t.string :from_commit
      t.string :to_commit
      t.string :status, null: false, default: "running" # running / succeeded / failed
      t.integer :changed_files_count, null: false, default: 0
      t.integer :matched_cves_count, null: false, default: 0
      t.text :error_message
      t.datetime :started_at, null: false
      t.datetime :finished_at

      t.timestamps
    end
    add_index :cvelist_syncs, :status
  end
end
