# Matches a CVE record against monitored products (case-insensitive partial match).
# Only the strongest rule is reported per product.
#
#   strength 1 (vendor_product): affected vendor/product contains the product name or a vendor
#   strength 2 (alias):          affected product contains an alias
#   strength 3 (description):    an English description contains the product name or an alias
class ProductMatcher
  Match = Data.define(:product_name, :rule, :matched_term, :matched_text)

  def initialize(products = MonitoredProduct.all)
    @products = products
  end

  # Cheap pre-filter on the raw file before parsing JSON.
  def candidate?(raw_string)
    text = raw_string.downcase
    @products.any? { |product| product.all_terms.any? { |term| text.include?(term) } }
  end

  # Returns the strongest Match for each matching product.
  def match(record)
    @products.filter_map { |product| strongest_match(product, record) }
  end

  private
    def strongest_match(product, record)
      find(product, :vendor_product, product.primary_terms, affected_texts(record, include_vendor: true)) ||
        find(product, :alias, product.alias_terms, affected_texts(record, include_vendor: false)) ||
        find(product, :description, product.description_terms, record.english_descriptions)
    end

    def find(product, rule, terms, texts)
      texts.each do |text|
        term = terms.find { |t| text.downcase.include?(t) }
        return Match.new(product_name: product.name, rule: rule.to_s, matched_term: term, matched_text: text) if term
      end
      nil
    end

    def affected_texts(record, include_vendor:)
      record.affected.flat_map do |entry|
        texts = [ entry["product"], entry["packageName"] ]
        texts << entry["vendor"] if include_vendor
        texts
      end.compact.reject { |text| text.blank? || text.casecmp?("n/a") }
    end
end
