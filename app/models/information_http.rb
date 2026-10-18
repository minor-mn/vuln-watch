require "net/http"
require "openssl"

class InformationHttp
  class Error < StandardError
    attr_reader :retry_at
    def initialize(message, retry_at: nil)
      super(message)
      @retry_at = retry_at
    end
  end

  Response = Data.define(:body, :next_url)

  def initialize(transport: Net::HTTP)
    @transport = transport
  end

  # Callers pass only fixed feed URLs or validated story/message/API URLs.
  # Redirects are deliberately not followed, including for authenticated GitHub calls.
  def get(url, github: false)
    uri = URI(url)
    headers = { "User-Agent" => "vuln-watch/1.0 (personal information reader)" }
    if github
      raise Error, "Invalid GitHub API URL" unless InformationFeeds.github_api_url?(url)
      headers.merge!("Accept" => "application/vnd.github+json", "X-GitHub-Api-Version" => "2026-03-10")
      headers["Authorization"] = "Bearer #{ENV['GITHUB_ADVISORY_TOKEN']}" if ENV["GITHUB_ADVISORY_TOKEN"].present?
    end
    body = +""
    next_url = nil
    # Explicitly requested exception for Full Disclosure's feed and message pages.
    full_disclosure = url == InformationFeeds::FEEDS.fetch("full_disclosure") || InformationFeeds.message_url?(url)
    verify_mode = full_disclosure ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
    @transport.start(uri.host, uri.port, use_ssl: true, verify_mode:, open_timeout: 10, read_timeout: 15, write_timeout: 10) do |http|
      http.request(Net::HTTP::Get.new(uri, headers)) do |response|
        unless response.is_a?(Net::HTTPSuccess)
          delay = [ response["Retry-After"].to_i, 3600 ].max
          retry_at = Time.current + delay
          begin
            retry_at = [ retry_at, Time.httpdate(response["Retry-After"]) ].max if response["Retry-After"].present?
          rescue ArgumentError
          end
          retry_at = [ retry_at, Time.at(response["X-RateLimit-Reset"].to_i) ].max if response["X-RateLimit-Remaining"] == "0"
          raise Error.new("HTTP #{response.code} from #{uri.host}", retry_at:)
        end
        response.read_body do |chunk|
          body << chunk
          raise Error, "Response too large from #{uri.host}" if body.bytesize > (github ? 8_000_000 : 2_000_000)
        end
        next_url = response["Link"].to_s.split(",").find { |link| link.match?(/rel="next"/) }&.[](/<([^>]+)>/, 1)
      end
    end
    Response.new(body: body.force_encoding(Encoding::UTF_8).scrub, next_url:)
  rescue Timeout::Error, SocketError, SystemCallError, IOError, OpenSSL::SSL::SSLError => error
    raise Error, "Request failed: #{error.class}"
  end
end
