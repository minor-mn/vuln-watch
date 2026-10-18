class CreateFullDisclosureAnalyses < ActiveRecord::Migration[8.1]
  def change
    add_column :information_items, :full_body, :text
    add_column :information_items, :full_body_fetched_at, :datetime

    create_table :full_disclosure_analyses do |t|
      t.references :information_item, null: false, foreign_key: true
      t.string :input_hash, null: false
      t.text :title, null: false
      t.text :original_body, null: false
      t.text :body_ja, null: false
      t.jsonb :assessments, null: false, default: []
      t.string :model, null: false
      t.string :prompt_version, null: false
      t.datetime :analyzed_at, null: false
      t.jsonb :raw_response, null: false, default: {}
      t.timestamps
    end
    add_index :full_disclosure_analyses, [ :information_item_id, :input_hash ], unique: true, name: "index_fd_analyses_on_item_and_input"
  end
end
