class RemoveMatchedTextJaFromProductMatches < ActiveRecord::Migration[8.0]
  def change
    remove_column :product_matches, :matched_text_ja, :text
  end
end
