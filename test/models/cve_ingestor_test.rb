require "test_helper"

class CveIngestorTest < ActiveSupport::TestCase
  V31_NETWORK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".freeze
  V31_LOW_PRIV = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".freeze

  setup { @ingestor = CveIngestor.new(matcher: ProductMatcher.new(sample_products)) }

  test "stores a matching CVE with snapshot, match and CNA assessments" do
    result = @ingestor.ingest(cve_record(cna_vectors: [ V31_NETWORK ]))
    cve = result.cve

    assert_equal [ "cna" ], result.changed_sources
    assert cve.matched?
    assert cve.judged_unknown?
    assert_equal 1, cve.cve_snapshots.count
    assert_equal [ "Ruby on Rails" ], cve.product_matches.pluck(:product_name).uniq
    assert_equal [ "N" ], cve.current_assessments_by_source["cna"].map(&:privileges_required)
  end

  test "skips CVEs that match nothing" do
    assert_nil @ingestor.ingest(cve_record(vendor: "acme", product: "widget"))
    assert_equal 0, Cve.count
  end

  test "description-only matches are possible matches" do
    result = @ingestor.ingest(cve_record(vendor: "n/a", product: "n/a", description: "Works with Postgres."))

    assert result.cve.possible_match?
  end

  test "skips new CVEs published before watching started" do
    ingestor = CveIngestor.new(matcher: ProductMatcher.new(sample_products), published_after: Time.utc(2026, 10, 8))

    assert_nil ingestor.ingest(cve_record(published: "2026-10-07T23:59:59Z"))
    assert ingestor.ingest(cve_record(published: "2026-10-08T00:00:00Z"))
  end

  test "a CISA-only update adds a CISA revision and leaves CNA untouched" do
    @ingestor.ingest(cve_record(updated: "2026-10-01T09:00:00Z", cna_vectors: [ V31_NETWORK ]))

    result = @ingestor.ingest(cve_record(
      updated: "2026-10-01T12:00:00Z", cna_updated: "2026-10-01T09:00:00Z", cna_vectors: [ V31_NETWORK ],
      cisa_updated: "2026-10-01T12:00:00Z", cisa_vectors: [ V31_LOW_PRIV ]
    ))
    cve = result.cve

    assert_equal [ "cisa_adp" ], result.changed_sources
    assert_equal 2, cve.cve_snapshots.count
    assert_equal 1, cve.source_revisions.cna.count
    assert_equal Time.utc(2026, 10, 1, 12), cve.source_revisions.cisa_adp.sole.source_date_updated
    assert cve.assessment_mismatch
  end

  test "a record-only update adds a snapshot but no source revision" do
    @ingestor.ingest(cve_record(updated: "2026-10-01T09:00:00Z", cna_vectors: [ V31_NETWORK ]))

    result = @ingestor.ingest(cve_record(updated: "2026-10-05T00:00:00Z", cna_updated: "2026-10-01T09:00:00Z", cna_vectors: [ V31_NETWORK ]))

    assert_empty result.changed_sources
    assert_equal 2, result.cve.cve_snapshots.count
  end

  test "keeps an already stored CVE updated after it stops matching" do
    @ingestor.ingest(cve_record(updated: "2026-10-01T00:00:00Z"))
    ingestor = CveIngestor.new(matcher: ProductMatcher.new([]))

    result = ingestor.ingest(cve_record(updated: "2026-10-02T00:00:00Z", cna_updated: "2026-10-02T00:00:00Z", cna_vectors: [ V31_NETWORK ]))

    assert result.cve.matched?
    assert_equal 1, result.cve.product_matches.count
    assert_equal [ "cna" ], result.changed_sources
  end
end
