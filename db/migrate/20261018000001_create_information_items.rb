class CreateInformationItems < ActiveRecord::Migration[8.1]
  def change
    create_table :information_items do |t|
      t.string :source, null: false
      t.string :url, null: false
      t.text :title, null: false
      t.text :body, null: false, default: ""
      t.datetime :published_at, null: false
      t.datetime :fetched_at, null: false
      t.text :summary
      t.boolean :relevant
      t.boolean :listed, null: false, default: true
      t.string :summary_digest
      t.jsonb :details, null: false, default: {}
      t.jsonb :thread, null: false, default: {}
      t.timestamps
    end
    add_index :information_items, [ :source, :url ], unique: true
    add_index :information_items, [ :source, :listed, :published_at ]

    create_table :information_source_states do |t|
      t.string :source, null: false
      t.datetime :attempted_at
      t.datetime :succeeded_at
      t.datetime :retry_at
      t.text :error_message
      t.timestamps
    end
    add_index :information_source_states, :source, unique: true
  end
end
