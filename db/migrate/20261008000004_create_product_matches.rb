# Which monitored product a CVE matched, and by which rule.
# Rows are kept even after the product is removed from config/monitored_products.yml.
class CreateProductMatches < ActiveRecord::Migration[8.0]
  def change
    create_table :product_matches do |t|
      t.references :cve, null: false, foreign_key: true
      t.string :product_name, null: false            # monitored_products.yml `name`
      t.string :rule, null: false                    # vendor_product / alias / description
      t.string :matched_term, null: false            # the configured term that matched
      t.string :matched_text, null: false            # the CVE text it matched against (original case)
      t.string :ai_affects_product                   # possible_match only: true / false / unknown

      t.timestamps
    end
    add_index :product_matches, [ :cve_id, :product_name, :rule ], unique: true
  end
end
