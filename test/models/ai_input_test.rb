require "test_helper"

class AiInputTest < ActiveSupport::TestCase
  V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".freeze

  def digest(json, **options)
    AiInput.new(CveRecord.new(json), **options).digest
  end

  test "ignores references, unrelated ADP containers and the record's dateUpdated" do
    base = cve_json(cna_vectors: [ V31 ])
    changed = cve_json(cna_vectors: [ V31 ], updated: "2026-10-09T00:00:00Z", cna_updated: "2026-10-01T00:00:00.000Z")
    changed["containers"]["cna"]["references"] = [ { "url" => "https://example.com/advisory" } ]
    changed["containers"]["adp"] << { "providerMetadata" => { "shortName" => "other" }, "metrics" => [ { "cvssV3_1" => { "vectorString" => V31 } } ] }

    assert_equal digest(base), digest(changed)
  end

  test "changes when a CISA assessment is added" do
    assert_not_equal digest(cve_json(cna_vectors: [ V31 ])),
      digest(cve_json(cna_vectors: [ V31 ], cisa_updated: "2026-10-02T00:00:00Z", cisa_vectors: [ V31.sub("PR:N", "PR:L") ]))
  end

  test "does not depend on key order" do
    json = cve_json
    json["containers"]["cna"]["affected"] = [ { "product" => "rails", "vendor" => "rails" } ]

    assert_equal digest(cve_json), digest(json)
  end

  test "includes products matched only by description" do
    cve = ingest(vendor: "acme", product: "widget", description: "Uses Postgres.").cve

    assert_equal [ "PostgreSQL" ], AiInput.for(cve).to_h["products_to_verify"]
  end
end
