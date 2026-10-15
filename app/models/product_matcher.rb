# Matches declared product identities, not mentions of a dependency or its vendor.
# Description-only candidates are kept when affected-product information is incomplete.
class ProductMatcher
  UNKNOWN_IDENTITIES = [ "", "n/a", "na", "unknown", "unspecified", "not specified", "not applicable", "*", "-" ].freeze
  Match = Data.define(:product_name, :rule, :matched_term, :matched_text)

  def initialize(products = MonitoredProduct.all)
    @products = products
  end

  def candidate?(raw_string)
    text = raw_string.downcase
    @products.any? { |product| product.all_terms.any? { |term| text.include?(term) } }
  end

  def match(record)
    @products.filter_map { |product| affected_match(product, record) }
  end

  def product_names
    @products.map(&:name)
  end

  private
    def affected_match(product, record)
      entries = record.affected
      entries.each do |entry|
        identities(entry).each do |text|
          if identity(text) == identity(product.name)
            return Match.new(product_name: product.name, rule: "vendor_product", matched_term: normalized(product.name), matched_text: text)
          end

          vendor = normalized(entry["vendor"])
          known_vendors = [ product.name, *product.vendors ].map { |value| identity(value) }
          next unless UNKNOWN_IDENTITIES.include?(vendor) || known_vendors.include?(identity(vendor))

          term = product.aliases.find { |value| identity(text) == identity(value) }
          next unless term

          primary = product.primary_terms.any? { |value| identity(value) == identity(term) }
          return Match.new(product_name: product.name, rule: primary ? "vendor_product" : "alias", matched_term: normalized(term), matched_text: text)
        end
      end

      return if entries.any? && entries.all? { |entry| identities(entry).any? }

      record.english_texts.each do |text|
        term = product.description_terms.find { |value| text.match?(/(?:\A|\W)#{Regexp.escape(value)}(?=\W|\z)/i) }
        return Match.new(product_name: product.name, rule: "description", matched_term: term, matched_text: text) if term
      end
      nil
    end

    def identities(entry)
      [ entry["product"], entry["packageName"] ].compact.reject { |value| UNKNOWN_IDENTITIES.include?(normalized(value)) }
    end

    def normalized(value)
      value.to_s.strip.downcase
    end

    def identity(value)
      normalized(value).gsub(/[\s_-]+/, "")
    end
end
