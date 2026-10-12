# One version of a CNA or CISA-ADP container, identified by its own
# providerMetadata.dateUpdated. A new row is added only when that date changes.
class CreateSourceRevisions < ActiveRecord::Migration[8.0]
  def change
    create_table :source_revisions do |t|
      t.references :cve, null: false, foreign_key: true
      t.references :cve_snapshot, null: false, foreign_key: true
      t.string :source, null: false                  # cna / cisa_adp
      t.datetime :source_date_updated, null: false   # containers.*.providerMetadata.dateUpdated

      t.timestamps
    end
    add_index :source_revisions, [ :cve_id, :source, :source_date_updated ], unique: true,
      name: "index_source_revisions_uniqueness"
  end
end
