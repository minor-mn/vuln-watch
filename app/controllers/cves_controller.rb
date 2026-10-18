class CvesController < ApplicationController
  SECTIONS = %w[emergency non_emergency unknown].freeze
  PAGE_SIZE = 50
  INFORMATION_PAGE_SIZE = 20

  def index
    @selected_sources = InformationSources.select(params[:sources])
    @information_sections = information_sections
    @full_disclosure_assessments = full_disclosure_assessments
    identifiers = @information_sections.values.flat_map { |section| section.fetch(:items).flat_map(&:cve_identifiers) }
    @related_cves = Cve.published.where(identifier: identifiers).index_by(&:identifier)
    @sections = SECTIONS.index_with do |result|
      scope = Cve.published.where(current_judgement: result)
      scope = scope.none unless @selected_sources.include?("cve")
      total = scope.count
      total_pages = [ (total.to_f / PAGE_SIZE).ceil, 1 ].max
      page = params["#{result}_page"].to_s.to_i.clamp(1, total_pages)

      cves = scope.includes(:product_matches, judgements: [ :ai_analysis, { selected_assessment: :source_revision } ])
        .order(date_published: :desc, identifier: :desc)
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)

      { cves:, total:, page:, total_pages: }
    end
    ids = @sections.values.flat_map { |section| section.fetch(:cves).map(&:id) }
    @products_by_cve = CveSnapshot.where(cve_id: ids).select("DISTINCT ON (cve_id) cve_id, raw_json")
      .order(:cve_id, record_date_updated: :desc, id: :desc)
      .to_h { |snapshot| [ snapshot.cve_id, CveRecord.new(snapshot.raw_json).affected_product_names ] }
  rescue ArgumentError => error
    render plain: error.message, status: :bad_request
  end

  def show
    @cve = Cve.find_by!(identifier: params[:id])
    @judgement = @cve.latest_judgement
    @judgements = @cve.judgements.includes(selected_assessment: :source_revision).order(effective_at: :desc, id: :desc)
    @analysis = @cve.latest_ai_analysis
    @assessments_by_source = @cve.current_assessments_by_source
    @record = @cve.latest_snapshot&.then { |snapshot| CveRecord.new(snapshot.raw_json) }
  end

  private
    def full_disclosure_assessments
      items = @information_sections.dig("full_disclosure", :items) || []
      hashes = items.filter_map do |item|
        [ item.id, FullDisclosureAnalysis.input_hash(item) ] if item.full_body.present?
      end.to_h
      return {} if hashes.empty?

      FullDisclosureAnalysis.where(information_item_id: hashes.keys, input_hash: hashes.values)
        .pluck(:information_item_id, :input_hash, :assessments).each_with_object({}) do |(id, input_hash, assessments), result|
          result[id] = assessments if hashes[id] == input_hash
        end
    end

    def information_sections
      sources = (InformationSources::LABELS.keys - [ "cve" ]) & @selected_sources
      sources.index_with do |source|
        scope = InformationItem.where(source:, listed: true, relevant: true).where(published_at: ..Time.current)
          .where("COALESCE(details ->> 'kind', '') != ?", "mailing_list_reply")
        total = scope.count
        total_pages = [ (total.to_f / INFORMATION_PAGE_SIZE).ceil, 1 ].max
        page_key = "#{source}_page"
        page = params[page_key].to_s.to_i.clamp(1, total_pages)
        items = scope.order(published_at: :desc, id: :desc).limit(INFORMATION_PAGE_SIZE).offset((page - 1) * INFORMATION_PAGE_SIZE)
        { items:, total:, page:, total_pages:, page_key: }
      end
    end
end
