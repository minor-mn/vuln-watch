class InformationCollector
  def initialize(feeds: InformationFeeds.new, summarizer: InformationSummarizer.new, threads: InformationThreads.new)
    @feeds, @summarizer, @threads = feeds, summarizer, threads
  end

  def call(source, now: Time.current)
    rows = @feeds.fetch(source, now:)
    items = InformationItem.transaction do
      # A rolling feed no longer containing an older post does not invalidate its archive.
      # Only remove missing entries inside the date range covered by this fetch.
      if rows.any?
        oldest = rows.map { |row| row.fetch(:published_at) }.min
        InformationItem.where(source:, published_at: oldest..now)
          .where.not(url: rows.map { |row| row.fetch(:url) }).update_all(listed: false)
      end
      rows.map do |attributes|
        item = InformationItem.find_or_initialize_by(source:, url: attributes.fetch(:url))
        changed = item.new_record? || item.title != attributes[:title] || item.body != attributes[:body]
        item.assign_attributes(attributes.merge(fetched_at: now, listed: true))
        item.assign_attributes(summary: nil, summary_digest: nil, relevant: source != "slashdot" || "#{item.title} #{item.body}".match?(/\b(?:AI|LLM|GPT|artificial intelligence|machine learning|security|vulnerabilit\w*|malware|ransomware|breach|hack\w*|exploit\w*|privacy|encryption)\b/i)) if changed
        item.save!
        item
      end
    end
    @summarizer.call(items)
    items.reject { |item| item.reply? || item.relevant != true }.each do |item|
      item.update!(thread: @threads.fetch(item))
    end
  end
end
