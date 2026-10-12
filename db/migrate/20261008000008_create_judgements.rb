# Judgement history. A row is added only when the judgement or its inputs change.
class CreateJudgements < ActiveRecord::Migration[8.0]
  def change
    create_table :judgements do |t|
      t.references :cve, null: false, foreign_key: true
      t.string :result, null: false                  # emergency / non_emergency / unknown
      t.string :attack_condition, null: false        # condition 1: met / not_met / unknown
      t.string :capability_condition, null: false    # condition 2: met / not_met / unknown
      t.references :selected_assessment, foreign_key: { to_table: :cvss_assessments }
      t.references :ai_analysis, foreign_key: true
      t.datetime :effective_at, null: false          # source dateUpdated that caused this judgement
      t.jsonb :changes_summary, null: false, default: [] # e.g. [{ source: "cna", field: "PR", from: "N", to: "L" }]

      t.timestamps
    end
    add_index :judgements, [ :cve_id, :effective_at ]
  end
end
