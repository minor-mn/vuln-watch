require "test_helper"

class ProductMatcherTest < ActiveSupport::TestCase
  setup { @matcher = ProductMatcher.new(sample_products) }

  test "matches affected vendor/product case-insensitively" do
    matches = @matcher.match(cve_record(vendor: "n/a", product: "PostgreSQL"))

    assert_equal [ [ "PostgreSQL", "vendor_product", "postgresql", "PostgreSQL" ] ],
      matches.map { |m| m.to_h.values_at(:product_name, :rule, :matched_term, :matched_text) }
  end

  test "matches aliases against affected product" do
    matches = @matcher.match(cve_record(vendor: "rails", product: "ActiveStorage"))

    assert_equal [ "alias" ], matches.map(&:rule)
  end

  test "matches descriptions only as a weaker rule" do
    matches = @matcher.match(cve_record(vendor: "n/a", product: "n/a", description: "Widget uses Postgres for storage."))

    assert_equal [ [ "PostgreSQL", "description" ] ], matches.map { |m| [ m.product_name, m.rule ] }
  end

  test "returns nothing for unrelated CVEs" do
    assert_empty @matcher.match(cve_record(vendor: "acme", product: "widget"))
  end

  test "pre-filters raw text" do
    assert @matcher.candidate?(%({"product": "PostgreSQL"}))
    assert_not @matcher.candidate?(%({"product": "widget"}))
  end

  test "configured PostgreSQL matches its identity rather than a vendor or package substring" do
    postgres = MonitoredProduct.all.find { |product| product.name == "PostgreSQL" }
    matcher = ProductMatcher.new([ postgres ])

    assert_equal "vendor_product", matcher.match(cve_record(vendor: "n/a", product: "  POSTGRESQL  ")).sole.rule
    assert_equal "alias", matcher.match(cve_record(vendor: "postgresql", product: "postgres")).sole.rule
    assert_equal "alias", matcher.match(cve_record(vendor: "PostgreSQL Global Development Group", product: "PostgreSQL Server")).sole.rule
    assert_empty matcher.match(cve_record(vendor: "porsager", product: "postgres"))

    [ [ "Canonical", "postgresql-operator", "charmed-postgresql" ],
      [ "pgjdbc", "pgjdbc", "org.postgresql:postgresql" ],
      [ "PostgreSQL", "psqlODBC", nil ],
      [ "DALIBO", "PostgreSQL Anonymizer", nil ],
      [ "payloadcms", "db-postgres", nil ],
      [ "Red Hat", "Postgres exporter", "postgres-exporter-rhel9" ],
      [ "pgpointcloud", "pointcloud", nil ] ].each do |vendor, product, package|
      json = cve_json(vendor: vendor, product: product, description: "SQL injection when this application uses PostgreSQL.")
      json["containers"]["cna"]["affected"].first["packageName"] = package if package
      assert_empty matcher.match(CveRecord.new(json)), "Unexpected PostgreSQL match for #{product}"
    end
  end

  test "exact matching keeps core SQL injection and incomplete product records" do
    matcher = ProductMatcher.new([ MonitoredProduct.all.find { |product| product.name == "PostgreSQL" } ])
    core = cve_record(vendor: "PostgreSQL", product: "PostgreSQL", description: "SQL injection in PostgreSQL quoting APIs.")
    assert_equal "vendor_product", matcher.match(core).sole.rule

    unknown = cve_record(vendor: "n/a", product: "n/a", description: "A flaw in PostgreSQL.")
    assert_equal "description", matcher.match(unknown).sole.rule

    mixed = cve_json(vendor: "acme", product: "widget", description: "A flaw in PostgreSQL.")
    mixed["containers"]["cna"]["affected"] << { "vendor" => "n/a", "product" => "n/a" }
    assert_equal "description", matcher.match(CveRecord.new(mixed)).sole.rule
  end

  test "every monitored product rejects another application's description and a vendor-only match" do
    MonitoredProduct.all.each do |product|
      matcher = ProductMatcher.new([ product ])
      unrelated = cve_record(vendor: "acme", product: "widget", description: "SQL injection in an application using #{product.name}.")
      assert_empty matcher.match(unrelated), product.name

      vendor_only = cve_record(vendor: product.vendors.first || product.name, product: "different-tool", description: "Uses #{product.name}.")
      assert_empty matcher.match(vendor_only), product.name

      core = cve_record(vendor: "n/a", product: product.name, description: "A vulnerability in #{product.name}.")
      assert_equal product.name, matcher.match(core).sole.product_name
    end
  end

  test "every monitored product keeps incomplete records as candidates" do
    MonitoredProduct.all.each do |product|
      matcher = ProductMatcher.new([ product ])
      record = cve_record(vendor: "n/a", product: "n/a", description: "A vulnerability in #{product.name}.")
      assert_equal "description", matcher.match(record).sole.rule
    end
  end
end
