# Everything after a CVE is ingested: AI analysis, judgement, the emergency email and the
# translation of matched texts.
class CveEvaluation
  def initialize(analyzer: CveAnalyzer.new, notifier: EmergencyNotifier.new, translator: MatchedTextTranslator.new)
    @analyzer = analyzer
    @notifier = notifier
    @translator = translator
  end

  # When the AI call fails, the CVE is still judged (with the previous analysis, so that a
  # temporary failure does not flip the judgement) and the error is raised afterwards so that
  # the caller can retry.
  def call(cve, changed_sources: [])
    error = nil
    analysis =
      begin
        @analyzer.analyze(cve)
      rescue OpenaiClient::Error => e
        error = e
        nil
      end

    cve.reload
    CveJudge.new(cve).judge(analysis: analysis || cve.latest_ai_analysis, changed_sources:)
    @notifier.notify(cve)

    # The translation is only for display, so it never holds up judging or notifying.
    begin
      @translator.translate(cve)
    rescue OpenaiClient::Error => e
      error ||= e
    end
    raise error if error
  end
end
