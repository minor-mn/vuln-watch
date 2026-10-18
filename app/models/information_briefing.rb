class InformationBriefing
  def initialize(sources: InformationSources.enabled, now: Time.current, selection: nil)
    @selection = selection || BriefingSelection.new(now:)
    @sources, @now = sources, @selection.now
  end

  def external_items
    @external_items ||= (@sources - [ "cve" ]).flat_map do |source|
      if @selection.custom?
        scope = InformationItem.where(source:, listed: true, relevant: true)
          .where("COALESCE(details ->> 'kind', '') != ?", "mailing_list_reply")
          .order(published_at: :desc, id: :desc)
        @selection.apply(scope, date: :published_at).to_a
      else
        InformationItem.selected(source, now: @now).to_a.select { |item| item.relevant == true && !item.reply? }
      end
    end
  end

  def sections
    ids = external_items.flat_map(&:cve_identifiers)
    cves = Cve.published.where(identifier: ids).index_by(&:identifier)
    external_items.group_by { |item| item.section(cves) }
  end

  def as_json(*)
    pairs = external_items.map { |item| [ external(item), item.thread ] }
    pairs.concat(cve_items) if @sources.include?("cve")
    # Security information comes first; Slashdot is always the final topics section.
    pairs.sort_by! { |item, _| [ item[:source][:publisher] == "Slashdot" ? 1 : 0, -Time.iso8601(item[:source][:published_at]).to_f, item[:source][:url] ] }
    items = pairs.map(&:first)
    threads = pairs.map do |item, thread|
      thread.presence || { title: item[:source][:title], url: item[:source][:url], fetched_at: @now.iso8601,
                          status: item[:source][:kind] == "advisory" ? "not_applicable" : "unavailable", comments: [], kind: item[:source][:kind] == "advisory" ? "advisory" : "comments", partial: false }
    end
    states = InformationSourceState.where(source: @sources).index_by(&:source)
    status = @sources.to_h do |source|
      state = states[source]
      [ source, { last_attempt_at: state&.attempted_at&.iso8601, last_success_at: state&.succeeded_at&.iso8601,
                  stale: state&.succeeded_at.nil? || state.succeeded_at < @now - 2.hours, error: state&.error_message.present? } ]
    end
    warnings = status.filter_map do |source, state|
      "#{InformationSources::LABELS.fetch(source)}の取得が未完了か、更新が遅れています。" if state[:stale] || state[:error]
    end
    warnings << "一部の話題は日本語要約が未作成です。" if external_items.any? { |item| item.summary.blank? }
    warnings << "スレッドのコメント・返信の一部または全部を取得できませんでした。" if threads.any? { |thread| thread["status"] == "unavailable" || thread["partial"] }
    text = items.first(4).map { |item| item[:summary] }
    text << "ほかにも#{items.size - 4}件の話題があります。" if items.size > 4
    text << (items.empty? ? "紹介できる話題はまだありません。" : "どの話題が気になりますか？")
    dates = items.map { |item| Time.iso8601(item[:source][:published_at]) }
    since = @selection.custom? ? @selection.since : ([ @selection.since ] + dates).min
    { version: 1, news: { since: since.iso8601, as_of: @now.iso8601,
                         selection_policy: @selection.policy, hours: @selection.hours, limit: @selection.limit,
                         text: text.join("\n"), items: }, threads:, warnings:, sources: status }
  end

  private
    def external(item)
      { summary: item.summary.presence || item.title, article_summary: item.body.first(600),
        advisory: item.source == "github_advisory" ? item.details.except("kind") : nil,
        source: { title: item.title, url: item.url, publisher: InformationSources::LABELS.fetch(item.source),
                  published_at: item.published_at.iso8601, kind: item.details.fetch("kind", "report") } }
    end

    def cve_items
      scope = Cve.published.order(date_published: :desc, identifier: :desc)
      selected = @selection.apply(scope, date: :date_published)
      selected.map do |cve|
        analysis = cve.latest_ai_analysis
        snapshot = cve.latest_snapshot
        product = snapshot && CveRecord.new(snapshot.raw_json).affected_product_names.join("、")
        title = [ cve.identifier, product.presence ].compact.join("：")
        overview = analysis&.summary_overview.presence
        summary = overview && overview.length <= 60 ? overview : "#{cve.identifier}の脆弱性情報があります。"
        body = { overview:, impact: analysis&.summary_impact, affected: analysis&.summary_affected,
                 mitigation: analysis&.summary_mitigation, judgement: cve.current_judgement,
                 description: snapshot&.raw_json&.dig("containers", "cna", "descriptions") }
        item = { summary:, article_summary: JSON.generate(body), advisory: { "cve_id" => cve.identifier },
                 source: { title:, url: "https://www.cve.org/CVERecord?id=#{cve.identifier}", publisher: "CVE", published_at: cve.date_published.iso8601, kind: "advisory" } }
        [ item, { title:, url: item[:source][:url], fetched_at: @now.iso8601, status: "not_applicable", comments: [], kind: "advisory", partial: false } ]
      end
    end
end
