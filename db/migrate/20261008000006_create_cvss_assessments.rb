# A CVSS v3.0+ assessment found in a source revision. Never updated in place.
class CreateCvssAssessments < ActiveRecord::Migration[8.0]
  def change
    create_table :cvss_assessments do |t|
      t.references :source_revision, null: false, foreign_key: true
      t.string :version, null: false                 # 4.0 / 3.1 / 3.0
      t.string :attack_vector, null: false           # N / A / L / P
      t.string :privileges_required, null: false     # N / L / H
      t.string :user_interaction, null: false        # N / R (v3) / P / A (v4)
      t.string :vector_string, null: false

      t.timestamps
    end
    add_index :cvss_assessments, [ :source_revision_id, :version ], unique: true
  end
end
