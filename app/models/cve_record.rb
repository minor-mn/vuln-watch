# Read-only view over a CVE JSON 5.x record.
class CveRecord
  CISA_ADP_SHORT_NAME = "CISA-ADP".freeze
  METRIC_KEYS = { "cvssV4_0" => "4.0", "cvssV3_1" => "3.1", "cvssV3_0" => "3.0" }.freeze

  # One CVSS assessment extracted from a container.
  Assessment = Data.define(:version, :attack_vector, :privileges_required, :user_interaction, :vector_string)

  attr_reader :json

  def self.parse(string)
    new(JSON.parse(string))
  end

  def initialize(json)
    @json = json
  end

  def identifier = metadata.fetch("cveId")
  def state = metadata.fetch("state")
  def date_published = parse_time(metadata["datePublished"])
  def record_date_updated = parse_time(metadata["dateUpdated"]) || date_published

  def cna
    json.dig("containers", "cna") || {}
  end

  def cisa_adp
    Array(json.dig("containers", "adp")).find do |container|
      container.dig("providerMetadata", "shortName") == CISA_ADP_SHORT_NAME
    end
  end

  # { "cna" => container, "cisa_adp" => container } for the sources present.
  def source_containers
    { "cna" => cna.presence, "cisa_adp" => cisa_adp }.compact
  end

  def source_date_updated(container)
    parse_time(container.dig("providerMetadata", "dateUpdated"))
  end

  def affected
    Array(cna["affected"])
  end

  # Use the same source/version priority before import and after storage.
  def selected_assessment
    CvssAssessment.preferred(source_containers.transform_values { |container| assessments(container) })
  end

  def remotely_exploitable_without_interaction?
    assessment = selected_assessment
    assessment && [ assessment.attack_vector, assessment.privileges_required, assessment.user_interaction ] == %w[N N N]
  end

  def affected_product_names
    affected.filter_map do |entry|
      [ entry["product"], entry["vendor"] ].find { |name| name.present? && !%w[n/a unknown].include?(name.to_s.downcase) }
    end.uniq
  end

  # Reference links of the CNA and CISA containers, without duplicates.
  def references
    source_containers.values.flat_map { |container| Array(container["references"]) }
      .select { |reference| reference["url"].present? }
      .uniq { |reference| reference["url"] }
  end

  def english_descriptions
    english_values(cna["descriptions"])
  end

  def title
    cna["title"].presence
  end

  # Configurations required for the vulnerability to apply (e.g. "IPsec VPN is configured").
  def english_configurations
    english_values(cna["configurations"])
  end

  # Free text compared against product names: title, descriptions and configurations.
  def english_texts
    [ title, *english_descriptions, *english_configurations ].compact
  end

  # v3.0+ assessments in a container, at most one per version.
  def assessments(container)
    Array(container["metrics"]).each_with_object({}) do |metric, found|
      METRIC_KEYS.each do |key, version|
        next if found.key?(version) || !metric[key].is_a?(Hash)

        assessment = build_assessment(version, metric[key])
        found[version] = assessment if assessment
      end
    end.values
  end

  private
    def english_values(entries)
      Array(entries).select { |d| d["lang"].to_s.start_with?("en") }.map { |d| d["value"] }
    end

    def metadata
      json.fetch("cveMetadata")
    end

    def build_assessment(version, cvss)
      vector = cvss["vectorString"].to_s
      parts = vector.split("/").filter_map { |part| part.split(":", 2) if part.include?(":") }.to_h
      av, pr, ui = parts.values_at("AV", "PR", "UI")
      return if [ av, pr, ui ].any?(&:blank?)

      Assessment.new(version:, attack_vector: av, privileges_required: pr, user_interaction: ui, vector_string: vector)
    end

    # CVE dates may omit the time zone; they are UTC.
    def parse_time(value)
      return if value.blank?

      value = "#{value}Z" unless value.match?(/(Z|[+-]\d{2}:?\d{2})\z/)
      Time.iso8601(value)
    rescue ArgumentError
      Time.zone.parse(value)
    end
end
