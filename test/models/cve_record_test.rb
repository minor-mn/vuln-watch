require "test_helper"

class CveRecordTest < ActiveSupport::TestCase
  test "reads metadata and treats dates without a zone as UTC" do
    record = cve_record(published: "2026-10-01T09:00:00", updated: "2026-10-02T12:00:00.000Z")

    assert_equal "CVE-2026-0001", record.identifier
    assert_equal Time.utc(2026, 10, 1, 9), record.date_published
    assert_equal Time.utc(2026, 10, 2, 12), record.record_date_updated
  end

  test "extracts v3.0+ assessments from the vector string, one per version" do
    json = cve_json(cna_vectors: [
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    ])
    json["containers"]["cna"]["metrics"] << { "cvssV2_0" => { "vectorString" => "AV:N/AC:L/Au:N/C:P/I:P/A:P" } }
    record = CveRecord.new(json)

    assessments = record.assessments(record.cna)

    assert_equal [ "4.0", "3.1" ], assessments.map(&:version)
    assert_equal [ "N", "N", "P" ], assessments.first.to_h.values_at(:attack_vector, :privileges_required, :user_interaction)
    assert_equal "L", assessments.second.privileges_required
  end

  test "finds the CISA-ADP container among other ADP containers" do
    record = cve_record(cisa_updated: "2026-10-03T00:00:00Z", cisa_vectors: [ "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" ])

    assert_equal %w[cna cisa_adp], record.source_containers.keys
    assert_equal Time.utc(2026, 10, 3), record.source_date_updated(record.cisa_adp)
  end
end
