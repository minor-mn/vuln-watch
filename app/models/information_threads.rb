require "set"

class InformationThreads
  MAX_COMMENTS = 12
  MAX_CHARS = 1200

  def initialize(http: InformationHttp.new)
    @http = http
  end

  def fetch(item)
    kind = { "full_disclosure" => "mailing_list_replies", "github_advisory" => "advisory" }.fetch(item.source, "comments")
    result = { "title" => item.title, "url" => item.url, "fetched_at" => Time.current.iso8601,
               "status" => "not_applicable", "kind" => kind, "comments" => [], "partial" => false }
    return result if item.source == "github_advisory"
    result["status"] = "empty"
    if item.source == "slashdot"
      raise InformationHttp::Error, "Invalid story URL" unless InformationFeeds.slashdot_url?(item.url)
      uri = URI(item.url)
      uri.query = "threshold=-1&mode=flat&no_d2=1"
      comments = slashdot(@http.get(uri.to_s).body, item.url)
      result["partial"] = comments.size > MAX_COMMENTS
      result["comments"] = comments.sort_by { |row| -(row["score"] || -2) }.first(MAX_COMMENTS)
    elsif item.source == "full_disclosure"
      root = message(@http.get(item.url).body, item.url, include_quotes: true)
      result["original_body"] = root.fetch(:text)
      descendants = root.fetch(:parents).keys.select do |candidate|
        current = candidate
        seen = Set.new
        loop do
          break false unless seen.add?(current)
          current = root[:parents][current]
          break true if current == item.url
          break false if current.nil?
        end
      end
      result["partial"] = descendants.size > MAX_COMMENTS
      result["comments"] = descendants.first(MAX_COMMENTS).filter_map do |url|
        reply = message(@http.get(url).body, url)
        text = reply[:text].lines.reject { |line| line.lstrip.start_with?(">") }.join.split(/\n_{10,}\s*\nSent through the Full Disclosure mailing list/, 2).first.to_s.strip
        raise InformationHttp::Error, "Empty reply" if text.empty?
        comment(url, reply[:title], text, url, nil, root[:parents][url])
      rescue InformationHttp::Error
        result["partial"] = true
        nil
      end
      result["status"] = "unavailable" if descendants.any? && result["comments"].empty?
    end
    result["status"] = "available" if result["comments"].any?
    result
  rescue InformationHttp::Error, URI::InvalidURIError, ArgumentError
    result.merge("status" => "unavailable")
  end

  def slashdot(html, url)
    doc = Nokogiri::HTML(html)
    doc.css("script, style").remove
    doc.css("[id^='comment_']").filter_map do |node|
      id = node["id"][/\Acomment_(\d+)\z/, 1]
      next unless id
      body = doc.at_css("#comment_body_#{id}")
      next if body.nil? || body.text.strip.empty?
      body.css("br").each { |element| element.replace(" ") }
      body.css("p, div").each { |element| element.add_previous_sibling(Nokogiri::XML::Text.new(" ", doc)) }
      title = doc.at_css("#comment_link_#{id}")
      score = doc.at_css("#comment_score_#{id}")&.text&.[](/Score:\s*(-?\d+)/, 1)&.to_i
      parent = node.ancestors.find { |ancestor| ancestor["id"].to_s.match?(/\Acommtree_\d+\z/) }&.[]("id")&.delete_prefix("commtree_")
      link = title&.[]("href")&.then { |href| URI.join(url, href).to_s }
      link = "#{url}#comment_#{id}" unless InformationFeeds.valid_url?(link, host: URI(url).host)
      row = comment(id, title&.text.to_s, body.text.gsub(/\s+/, " ").strip, link, score, parent)
      row["truncated"] ||= body.at_css(".substr").present?
      row
    end
  end

  def message(html, url, include_quotes: false)
    raise InformationHttp::Error, "Invalid message URL" unless InformationFeeds.message_url?(url)
    body = html[/<!--\s*X-Body-of-Message\s*-->(.*?)<!--\s*X-Body-of-Message-End\s*-->/m, 1]
    raise InformationHttp::Error, "Missing message body" unless body
    fragment = Nokogiri::HTML.fragment(body)
    fragment.css(include_quotes ? "script, style" : "script, style, blockquote").remove
    fragment.css("br").each { |node| node.replace("\n") }
    fragment.css("p, div, li, h1, h2, h3, h4, pre").each do |node|
      node.add_previous_sibling(Nokogiri::XML::Text.new("\n", fragment.document))
      node.add_next_sibling(Nokogiri::XML::Text.new("\n", fragment.document))
    end
    doc = Nokogiri::HTML(html)
    title = doc.at_css("h1.m-title")&.text.to_s.strip
    parents = {}
    thread = doc.css("ul.thread").last
    rows = {}
    thread&.css("li")&.each do |li|
      # Only links owned by this li, not those in descendant replies.
      link = li.css("a, strong").find { |node| node.ancestors("li").first == li }
      next unless link
      target = link.name == "strong" ? url : URI.join(url, link["href"].to_s).to_s
      rows[li] = target if InformationFeeds.message_url?(target)
    end
    rows.each { |li, target| parents[target] = rows[li.ancestors("li").first] }
    raise InformationHttp::Error, "Missing message/thread" if title.empty? || fragment.text.strip.empty? || !parents.key?(url)
    { title:, text: fragment.text.strip, parents: }
  rescue URI::InvalidURIError
    raise InformationHttp::Error, "Invalid thread link"
  end

  private
    def comment(id, title, text, url, score, parent)
      { "id" => id, "title" => title.gsub(/\s+/, " ").strip, "text" => text.first(MAX_CHARS), "url" => url,
        "score" => score, "parent_id" => parent, "truncated" => text.length > MAX_CHARS }
    end
end
