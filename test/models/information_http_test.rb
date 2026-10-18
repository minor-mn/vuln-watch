require "test_helper"

class InformationHttpTest < ActiveSupport::TestCase
  class Response < Net::HTTPOK
    def initialize
      super("1.1", "200", "OK")
    end

    def read_body
      yield "fixture body"
    end
  end

  class Transport
    attr_reader :connections, :requests

    def initialize
      @connections, @requests = [], []
    end

    def start(host, port, **options)
      @connections << { host:, port:, **options }
      yield self
    end

    def request(request)
      @requests << request
      yield Response.new
    end
  end

  test "only Full Disclosure feed and canonical message pages skip certificate verification" do
    transport = Transport.new
    http = InformationHttp.new(transport:)
    [ "https://seclists.org/rss/fulldisclosure.rss", "https://seclists.org/fulldisclosure/2026/Oct/1" ].each do |url|
      assert_equal "fixture body", http.get(url).body
      assert_equal OpenSSL::SSL::VERIFY_NONE, transport.connections.last[:verify_mode]
      assert transport.connections.last[:use_ssl]
    end
  end

  test "other feeds paths and lookalike hosts retain certificate verification" do
    transport = Transport.new
    http = InformationHttp.new(transport:)
    [ "https://rss.slashdot.org/Slashdot/slashdotMainatom", "https://seclists.org/rss/nmap-hackers.rss",
      "https://seclists.org.evil.example/rss/fulldisclosure.rss", "https://seclists.org:8443/fulldisclosure/2026/Oct/1" ].each do |url|
      http.get(url)
      assert_equal OpenSSL::SSL::VERIFY_PEER, transport.connections.last[:verify_mode]
    end
  end

  test "authenticated GitHub requests retain certificate verification and their own headers" do
    previous = ENV["GITHUB_ADVISORY_TOKEN"]
    ENV["GITHUB_ADVISORY_TOKEN"] = "test-token"
    transport = Transport.new
    http = InformationHttp.new(transport:)
    http.get("https://api.github.com/advisories", github: true)
    assert_equal OpenSSL::SSL::VERIFY_PEER, transport.connections.last[:verify_mode]
    assert_equal "Bearer test-token", transport.requests.last["Authorization"]
    http.get("https://seclists.org/rss/fulldisclosure.rss")
    assert_nil transport.requests.last["Authorization"]
  ensure
    ENV["GITHUB_ADVISORY_TOKEN"] = previous
  end
end
