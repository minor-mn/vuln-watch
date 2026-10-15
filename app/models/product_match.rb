class ProductMatch < ApplicationRecord
  belongs_to :cve

  # Ordered strongest first.
  enum :rule, { vendor_product: "vendor_product", alias: "alias", description: "description" },
    prefix: :by, validate: true

  validates :product_name, :matched_term, :matched_text, presence: true
end
