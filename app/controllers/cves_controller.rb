class CvesController < ApplicationController
  SECTIONS = %w[emergency non_emergency unknown].freeze

  def index
    cves = Cve.includes(:product_matches, judgements: [ :ai_analysis, { selected_assessment: :source_revision } ])
      .order(date_published: :desc, identifier: :desc)
    grouped = cves.group_by(&:current_judgement)
    @sections = SECTIONS.index_with { |result| grouped.fetch(result, []) }
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
