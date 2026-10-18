module Api
  class BriefingsController < ActionController::API
    def show
      response.headers["Cache-Control"] = "no-store"
      selection = BriefingSelection.new(hours: params[:hours], limit: params[:limit])
      render json: InformationBriefing.new(sources: InformationSources.select(params[:sources]), selection:).as_json
    rescue ArgumentError => error
      render json: { detail: error.message }, status: :bad_request
    end
  end
end
