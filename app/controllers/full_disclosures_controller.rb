class FullDisclosuresController < ApplicationController
  def show
    @item = InformationItem.where(source: "full_disclosure").find(params[:id])
    @analysis = @item.current_full_disclosure_analysis
    @source_url = "https://seclists.org#{URI(@item.url).path}" if InformationFeeds.message_url?(@item.url)
  end
end
