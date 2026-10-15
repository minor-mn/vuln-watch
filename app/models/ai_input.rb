# The information passed to OpenAI, extracted from the CVE record and normalized so that its
# SHA-256 changes only when something the AI looks at changes (not for added references,
# unrelated ADP containers or the record's dateUpdated).
class AiInput
  SOURCE_LABELS = { "cna" => "CNA", "cisa_adp" => "CISA-ADP" }.freeze

  attr_reader :record

  def self.for(cve)
    new(CveRecord.new(cve.latest_snapshot.raw_json))
  end

  def initialize(record)
    @record = record
  end

  def to_h
    {
      "cve_id" => record.identifier,
      "title" => record.title&.strip,
      "descriptions" => record.english_descriptions.map(&:strip),
      "configurations" => record.english_configurations.map(&:strip).presence,
      "affected" => record.affected.map { |entry| deep_sort(entry) },
      "cvss" => cvss
    }.compact
  end

  def digest
    Digest::SHA256.hexdigest(JSON.generate(to_h))
  end

  private
    def cvss
      record.source_containers.flat_map do |source, container|
        record.assessments(container)
          .sort_by { |assessment| CvssAssessment::VERSIONS.index(assessment.version) }
          .map { |assessment| { "source" => SOURCE_LABELS.fetch(source), "version" => assessment.version, "vector" => assessment.vector_string } }
      end
    end

    def deep_sort(value)
      case value
      when Hash then value.sort.to_h { |key, child| [ key, deep_sort(child) ] }
      when Array then value.map { |child| deep_sort(child) }
      else value
      end
    end
end
