ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"

module ActiveSupport
  class TestCase
    # Run tests in parallel with specified workers
    parallelize(workers: :number_of_processors)

    # Setup all fixtures in test/fixtures/*.yml for all tests in alphabetical order.
    fixtures :all

    # Builds a minimal CVE JSON 5.x record.
    def cve_json(id: "CVE-2026-0001", published: "2026-10-01T00:00:00.000Z", updated: published,
                 vendor: "rails", product: "rails", description: "A vulnerability.",
                 cna_updated: updated, cna_vectors: [], cisa_updated: nil, cisa_vectors: [])
      metric = ->(vector) { { "cvssV#{vector[/CVSS:(\d\.\d)/, 1].tr('.', '_')}" => { "vectorString" => vector } } }
      adp = [ { "providerMetadata" => { "shortName" => "CVE", "dateUpdated" => updated } } ]
      if cisa_updated
        adp << { "providerMetadata" => { "shortName" => "CISA-ADP", "dateUpdated" => cisa_updated },
                 "metrics" => cisa_vectors.map(&metric) }
      end

      {
        "dataType" => "CVE_RECORD",
        "cveMetadata" => { "cveId" => id, "state" => "PUBLISHED", "datePublished" => published, "dateUpdated" => updated },
        "containers" => {
          "cna" => {
            "providerMetadata" => { "shortName" => "GitHub_M", "dateUpdated" => cna_updated },
            "descriptions" => [ { "lang" => "en", "value" => description } ],
            "affected" => [ { "vendor" => vendor, "product" => product } ],
            "metrics" => cna_vectors.map(&metric)
          },
          "adp" => adp
        }
      }
    end

    def cve_record(**options)
      CveRecord.new(cve_json(**options))
    end

    # Stands in for OpenaiClient; returns the given capabilities and records the calls.
    class FakeOpenaiClient
      attr_reader :calls, :model

      def initialize(capabilities: {}, product_assessments: [], configured: true, error: nil)
        @capabilities = capabilities
        @product_assessments = product_assessments
        @configured = configured
        @error = error
        @model = "test-model"
        @calls = []
      end

      def configured? = @configured

      def structured_output(**request)
        @calls << request
        raise @error if @error

        output = {
          "capabilities" => AiAnalysis::CAPABILITIES.to_h { |c| [ c.to_s, @capabilities.fetch(c, "false") ] },
          "evidence" => [ { "capability" => "remote_code_execution", "source" => "CNA の説明文", "quote" => "A vulnerability." } ],
          "summary" => { "overview" => "概要", "impact" => "影響", "affected" => "対象", "mitigation" => "対策" },
          "product_assessments" => @product_assessments
        }
        OpenaiClient::Response.new(output:, raw: { "id" => "resp_test", "output" => [] })
      end
    end

    # Ingests a CVE record (keyword options as for cve_json) with the sample products.
    def ingest(**options)
      CveIngestor.new(matcher: ProductMatcher.new(sample_products)).ingest(cve_record(**options))
    end

    def sample_products
      [
        MonitoredProduct.new(name: "Ruby on Rails", vendors: [ "rails" ], aliases: [ "rails", "activestorage" ]),
        MonitoredProduct.new(name: "PostgreSQL", vendors: [ "postgresql" ], aliases: [ "postgres" ])
      ]
    end
  end
end
