class ProductMatch < ApplicationRecord
  belongs_to :cve

  # Ordered strongest first.
  enum :rule, { vendor_product: "vendor_product", alias: "alias", description: "description" },
    prefix: :by, validate: true
  enum :ai_affects_product, { yes: "true", no: "false", unknown: "unknown" },
    prefix: :ai_affects, validate: { allow_nil: true }

  validates :product_name, :matched_term, :matched_text, presence: true
end
