# One OpenAI call: capability classification and Japanese summary generated together.
# Reused while the normalized AI input (input_hash) stays the same.
class CreateAiAnalyses < ActiveRecord::Migration[8.0]
  def change
    create_table :ai_analyses do |t|
      t.references :cve, null: false, foreign_key: true
      t.string :input_hash, null: false              # SHA-256 of input
      t.jsonb :input, null: false
      t.string :model, null: false
      t.string :prompt_version, null: false
      t.datetime :analyzed_at, null: false

      # Capabilities: true / false / unknown
      t.string :remote_code_execution, null: false
      t.string :authentication_bypass, null: false
      t.string :shell_access, null: false
      t.string :root_access, null: false
      t.jsonb :evidence, null: false, default: []     # [{ capability:, source:, text: }]

      # Japanese summary
      t.text :summary_overview
      t.text :summary_impact
      t.text :summary_affected
      t.text :summary_mitigation

      t.jsonb :raw_response, null: false

      t.timestamps
    end
    add_index :ai_analyses, [ :cve_id, :input_hash, :model, :prompt_version ], unique: true,
      name: "index_ai_analyses_uniqueness"
  end
end
