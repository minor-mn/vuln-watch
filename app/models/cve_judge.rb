# Decides whether a CVE is an emergency, without looking at CVSS scores:
#
#   condition 1 (attack):     the adopted assessment has AV:N, PR:N and UI:N
#   condition 2 (capability): the AI found RCE, authentication bypass, shell or root access
#
# Either condition not met => non_emergency, both met => emergency, otherwise unknown.
#
# A new Judgement is recorded only when the result, the adopted assessment or the capabilities
# changed, so the judgements of a CVE form its history.
class CveJudge
  ASSESSMENT_FIELDS = { "AV" => :attack_vector, "PR" => :privileges_required, "UI" => :user_interaction }.freeze

  def initialize(cve)
    @cve = cve
  end

  # changed_sources: the sources (cna / cisa_adp) whose container changed in this ingest; the
  # judgement takes effect at their dateUpdated.
  # Returns the current Judgement.
  def judge(analysis:, changed_sources: [])
    selected = @cve.selected_assessment
    attack = attack_condition(selected)
    capability = capability_condition(analysis)
    result = combine(attack, capability)

    previous = @cve.latest_judgement
    changes = changes_since(previous, result:, selected:, analysis:)

    judgement =
      if changes.any?
        @cve.judgements.create!(
          result:,
          attack_condition: attack,
          capability_condition: capability,
          selected_assessment: selected,
          ai_analysis: analysis,
          effective_at: effective_at(changed_sources),
          changes_summary: changes
        )
      else
        previous
      end
    @cve.update!(current_judgement: result)
    judgement
  end

  private
    def attack_condition(selected)
      return "unknown" if selected.nil?

      selected.remotely_exploitable_without_interaction? ? "met" : "not_met"
    end

    def capability_condition(analysis)
      values = analysis&.capability_values&.values
      return "unknown" if values.blank?
      return "met" if values.include?("true")

      values.all?("false") ? "not_met" : "unknown"
    end

    def combine(attack, capability)
      conditions = [ attack, capability ]
      return "non_emergency" if conditions.include?("not_met")

      conditions.all?("met") ? "emergency" : "unknown"
    end

    # Each change is a hash with a "type": result / selected_assessment / assessment / capability.
    def changes_since(previous, result:, selected:, analysis:)
      return [ { "type" => "result", "from" => nil, "to" => result } ] if previous.nil?

      changes = assessment_changes(previous.selected_assessment, selected) +
        capability_changes(previous.ai_analysis, analysis)
      changes << { "type" => "result", "from" => previous.result, "to" => result } if previous.result != result
      changes
    end

    def assessment_changes(before, after)
      return [] if before == after

      if before.nil? || after.nil? || [ before.source, before.version ] != [ after.source, after.version ]
        return [ { "type" => "selected_assessment", "from" => assessment_key(before), "to" => assessment_key(after) } ]
      end

      ASSESSMENT_FIELDS.filter_map do |field, attribute|
        from, to = before.public_send(attribute), after.public_send(attribute)
        next if from == to

        { "type" => "assessment", "source" => after.source, "version" => after.version, "field" => field, "from" => from, "to" => to }
      end
    end

    def capability_changes(before, after)
      return [] if after.nil? || before == after

      before_values = before&.capability_values || {}
      after.capability_values.filter_map do |capability, to|
        from = before_values.fetch(capability, "unknown")
        next if from == to

        { "type" => "capability", "capability" => capability.to_s, "from" => from, "to" => to }
      end
    end

    def assessment_key(assessment)
      assessment && { "source" => assessment.source, "version" => assessment.version }
    end

    # The dateUpdated of the containers that changed, not the record's or our ingest time.
    def effective_at(changed_sources)
      revisions = @cve.current_source_revisions.to_a
      dates = revisions.select { |revision| changed_sources.include?(revision.source) }.map(&:source_date_updated)
      dates = revisions.map(&:source_date_updated) if dates.empty?
      dates.max || @cve.record_date_updated || Time.current
    end
end
