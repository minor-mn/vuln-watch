class InformationSources
  LABELS = {
    "cve" => "CVE", "full_disclosure" => "Full Disclosure",
    "github_advisory" => "GitHub Advisory Database", "slashdot" => "Slashdot"
  }.freeze

  def self.enabled
    configured = ENV["INFORMATION_SOURCES"]
    keys = if configured.nil?
      YAML.safe_load_file(Rails.root.join("config/information_sources.yml")).select { |_, enabled| enabled == true }.keys
    else
      configured.split(",").map(&:strip).reject(&:empty?)
    end
    invalid = keys - LABELS.keys
    raise ArgumentError, "Unknown information sources: #{invalid.join(', ')}" if invalid.any?
    keys.uniq
  end

  def self.select(requested = nil)
    return enabled if requested.nil?
    keys = Array(requested).flat_map { |key| key.to_s.split(",") }.reject(&:empty?)
    raise ArgumentError, "Unknown information sources" if (keys - LABELS.keys).any?
    enabled & keys
  end
end
