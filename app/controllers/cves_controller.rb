class CvesController < ApplicationController
  SECTIONS = %w[emergency non_emergency unknown].freeze
  PAGE_SIZE = 50

  def index
    @sections = SECTIONS.index_with do |result|
      scope = Cve.where(current_judgement: result)
      total = scope.count
      total_pages = [ (total.to_f / PAGE_SIZE).ceil, 1 ].max
      page = params["#{result}_page"].to_s.to_i.clamp(1, total_pages)

      cves = scope.includes(:product_matches, judgements: [ :ai_analysis, { selected_assessment: :source_revision } ])
        .order(date_published: :desc, identifier: :desc)
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)

      { cves:, total:, page:, total_pages: }
    end
  end

  def show
    @cve = Cve.find_by!(identifier: params[:id])
    @judgement = @cve.latest_judgement
    @judgements = @cve.judgements.includes(selected_assessment: :source_revision).order(effective_at: :desc, id: :desc)
    @analysis = @cve.latest_ai_analysis
    @assessments_by_source = @cve.current_assessments_by_source
    @record = @cve.latest_snapshot&.then { |snapshot| CveRecord.new(snapshot.raw_json) }
  end
end
