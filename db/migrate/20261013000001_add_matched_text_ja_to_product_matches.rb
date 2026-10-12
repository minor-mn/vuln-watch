# Japanese translation of matched_text, produced by OpenAI.
class AddMatchedTextJaToProductMatches < ActiveRecord::Migration[8.0]
  def change
    add_column :product_matches, :matched_text_ja, :text
  end
end
