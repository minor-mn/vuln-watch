require "set"

require "nokogiri"
require "time"
require "uri"

class InformationFeeds
  FEEDS = {
    "slashdot" => "https://rss.slashdot.org/Slashdot/slashdotMainatom",
    "full_disclosure" => "https://seclists.org/rss/fulldisclosure.rss"
  }.freeze

  def initialize(http: InformationHttp.new)
    @http = http
  end

  def self.valid_url?(url, host:, path: nil)
    uri = URI(url)
    uri.is_a?(URI::HTTPS) && uri.host == host && uri.userinfo.nil? && uri.port == 443 && (!path || uri.path.match?(path))
  rescue URI::InvalidURIError, TypeError, ArgumentError
    false
  end

  def self.github_api_url?(url)
    valid_url?(url, host: "api.github.com", path: %r{\A/advisories\z}) && URI(url).fragment.nil?
  end

  def self.message_url?(url)
    valid_url?(url, host: "seclists.org", path: %r{\A/fulldisclosure/\d{4}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d+\z})
  end

  def self.slashdot_url?(url)
    uri = URI(url)
    host = uri.host.to_s
    (host == "slashdot.org" || host.end_with?(".slashdot.org")) && valid_url?(url, host:, path: %r{\A/story/})
  rescue URI::InvalidURIError, TypeError, ArgumentError
    false
  end

  def self.normalize(rows, now:)
    rows.select { |row| row[:published_at] <= now }.group_by { |row| row[:url] }
      .values.map { |duplicates| duplicates.max_by { |row| row[:published_at] } }
      .sort_by { |row| row[:published_at] }.reverse
  end

  def fetch(source, now:)
    return github(now:) if source == "github_advisory"
    parse_feed(@http.get(FEEDS.fetch(source)).body, source, now:)
  end

  def parse_feed(body, source, now:)
    raise InformationHttp::Error, "Invalid feed XML" if body.bytesize > 1_000_000 || body.match?(/<!DOCTYPE|<!ENTITY/i)
    xml = Nokogiri::XML(body) { |config| config.strict.nonet }
    raise InformationHttp::Error, "Unexpected feed document" unless %w[rss RDF feed].include?(xml.root&.name)
    rows = xml.xpath("//*[local-name()='item' or local-name()='entry']").filter_map do |entry|
      value = ->(name) { entry.at_xpath("./*[local-name()='#{name}']")&.text.to_s.strip }
      date = %w[pubDate published date updated].map { |name| value.call(name) }.find(&:present?)
      next unless date&.match?(/(?:Z|[+-]\d{2}:?\d{2}|GMT|UTC)\z/i)
      published = Time.parse(date)
      title = plain(value.call("title"))
      link = value.call("link").presence || entry.xpath("./*[local-name()='link']").find { |node| node["rel"].nil? || node["rel"] == "alternate" }&.[]("href")
      next if title.blank? || (source == "slashdot" ? !self.class.slashdot_url?(link) : !self.class.message_url?(link))
      text = %w[description summary content encoded].map { |name| value.call(name) }.find(&:present?).to_s
      kind = source == "slashdot" ? "discussion" : title.match?(/\A\s*Re(?:\[\d+\])?\s*:/i) ? "mailing_list_reply" : "mailing_list"
      { url: link, title:, body: plain(text), published_at: published, details: { "kind" => kind } }
    rescue ArgumentError
      nil
    end
    self.class.normalize(rows, now:)
  rescue Nokogiri::XML::SyntaxError => error
    raise InformationHttp::Error, "Invalid feed XML: #{error.class}"
  end

  private
    def plain(text)
      Nokogiri::HTML.fragment(text).text.gsub(/\s+/, " ").strip
    end

    def github(now:)
      url = "https://api.github.com/advisories?type=reviewed&is_withdrawn=false&sort=published&direction=desc&per_page=100"
      rows = []
      seen = Set.new
      while url
        raise InformationHttp::Error, "Invalid advisory pagination" unless self.class.github_api_url?(url) && seen.add?(url)
        response = @http.get(url, github: true)
        payload = JSON.parse(response.body)
        raise InformationHttp::Error, "Invalid advisory response" unless payload.is_a?(Array)
        rows.concat(payload.filter_map { |row| advisory(row, now:) })
        break if payload.empty? || (rows.size >= 5 && rows.any? { |row| row[:published_at] < now - 24.hours })
        url = response.next_url
      end
      self.class.normalize(rows, now:)
    rescue JSON::ParserError => error
      raise InformationHttp::Error, "Invalid advisory JSON: #{error.class}"
    end

    def advisory(row, now:)
      return unless row.is_a?(Hash) && row["type"] == "reviewed" && row["withdrawn_at"].nil?
      url = row["html_url"]
      return unless self.class.valid_url?(url, host: "github.com", path: %r{\A/advisories/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\z})
      return unless URI(url).path.split("/").last == row["ghsa_id"] && row["summary"].is_a?(String) && row["summary"].present?
      published = Time.iso8601(row.fetch("published_at"))
      return if published > now || !row["published_at"].match?(/(?:Z|[+-]\d{2}:\d{2})\z/)
      { url:, title: row["summary"], body: row["description"].to_s, published_at: published,
        details: row.slice("ghsa_id", "cve_id", "severity", "updated_at", "github_reviewed_at", "vulnerabilities", "cvss", "cvss_severities", "cwes", "references").merge("kind" => "advisory") }
    rescue KeyError, ArgumentError, TypeError
      nil
    end
end
