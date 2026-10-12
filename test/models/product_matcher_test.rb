require "test_helper"

class ProductMatcherTest < ActiveSupport::TestCase
  setup { @matcher = ProductMatcher.new(sample_products) }

  test "matches affected vendor/product case-insensitively" do
    matches = @matcher.match(cve_record(vendor: "n/a", product: "PostgreSQL"))

    assert_equal [ [ "PostgreSQL", "vendor_product", "postgresql", "PostgreSQL" ] ],
      matches.map { |m| m.to_h.values_at(:product_name, :rule, :matched_term, :matched_text) }
  end

  test "matches aliases against affected product" do
    matches = @matcher.match(cve_record(vendor: "github", product: "ActiveStorage"))

    assert_equal [ "alias" ], matches.map(&:rule)
  end

  test "matches descriptions only as a weaker rule" do
    matches = @matcher.match(cve_record(vendor: "acme", product: "widget", description: "Widget uses Postgres for storage."))

    assert_equal [ [ "PostgreSQL", "description" ] ], matches.map { |m| [ m.product_name, m.rule ] }
  end

  test "returns nothing for unrelated CVEs" do
    assert_empty @matcher.match(cve_record(vendor: "acme", product: "widget"))
  end

  test "pre-filters raw text" do
    assert @matcher.candidate?(%({"product": "PostgreSQL"}))
    assert_not @matcher.candidate?(%({"product": "widget"}))
  end
end
