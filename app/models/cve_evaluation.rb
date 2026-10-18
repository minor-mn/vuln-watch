# Everything after a CVE is ingested: AI analysis, judgement and the emergency email.
class CveEvaluation
  def initialize(analyzer: CveAnalyzer.new, notifier: EmergencyNotifier.new)
    @analyzer = analyzer
    @notifier = notifier
  end

  # When the AI call fails, the CVE is still judged (with the previous analysis, so that a
  # temporary failure does not flip the judgement) and the error is raised afterwards so that
  # the caller can retry.
  def call(cve, changed_sources: [])
    return unless cve.reload.state == "PUBLISHED"

    error = nil
    analysis =
      begin
        @analyzer.analyze(cve) if cve.analysis_eligible?
      rescue OpenaiClient::Error => e
        error = e
        nil
      end

    cve.reload
    CveJudge.new(cve).judge(analysis: analysis || cve.latest_ai_analysis, changed_sources:)
    @notifier.notify(cve)

    raise error if error
  end
end
