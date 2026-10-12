module CvesHelper
  JUDGEMENT_LABELS = {
    "emergency" => "Emergency（緊急）",
    "non_emergency" => "Matched（該当）",
    "unknown" => "Unclassified（判定待ち）"
  }.freeze

  JUDGEMENT_BADGE_CLASSES = {
    "emergency" => "bg-red-100 text-red-800 ring-red-300",
    "non_emergency" => "bg-sky-100 text-sky-800 ring-sky-300",
    "unknown" => "bg-gray-100 text-gray-700 ring-gray-300"
  }.freeze

  SOURCE_LABELS = { "cna" => "CNA", "cisa_adp" => "CISA" }.freeze

  CAPABILITY_LABELS = {
    "remote_code_execution" => "RCE",
    "authentication_bypass" => "認証回避",
    "shell_access" => "シェル取得",
    "root_access" => "root 取得"
  }.freeze

  RULE_LABELS = {
    "vendor_product" => "影響製品欄（製品名・ベンダー名）",
    "alias" => "影響製品欄（別名）",
    "description" => "説明文"
  }.freeze

  CONDITION_LABELS = { "met" => "満たす", "not_met" => "満たさない", "unknown" => "不明" }.freeze
  TRI_STATE_LABELS = { "true" => "該当", "false" => "非該当", "unknown" => "不明" }.freeze

  def judgement_label(result)
    JUDGEMENT_LABELS.fetch(result.to_s, result.to_s)
  end

  def judgement_badge(result)
    tag.span judgement_label(result),
      class: "inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 ring-inset #{JUDGEMENT_BADGE_CLASSES[result.to_s]}"
  end

  def possible_match_badge
    tag.span "説明文のみで一致", class: "inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 ring-inset bg-amber-50 text-amber-800 ring-amber-300"
  end

  def mismatch_badge
    tag.span "評価不一致", class: "inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 ring-inset bg-purple-50 text-purple-800 ring-purple-300"
  end

  def source_label(source)
    SOURCE_LABELS.fetch(source.to_s, source.to_s)
  end

  def assessment_vector(assessment)
    "AV:#{assessment.attack_vector} / PR:#{assessment.privileges_required} / UI:#{assessment.user_interaction}"
  end

  def assessment_origin(source, version)
    "#{source_label(source)}・CVSS #{version}"
  end

  def found_capabilities(analysis)
    return [] if analysis.nil?

    analysis.capability_values.select { |_, value| value == "true" }.keys.map { |c| CAPABILITY_LABELS.fetch(c.to_s) }
  end

  # e.g. "AV:N / PR:N / UI:N（CNA・CVSS 3.1）／ RCE"
  def judgement_basis(judgement)
    return "判定なし" if judgement.nil?

    assessment = judgement.selected_assessment
    parts = [ assessment ? "#{assessment_vector(assessment)}（#{assessment_origin(assessment.source, assessment.version)}）" : "採用評価なし" ]
    capabilities = found_capabilities(judgement.ai_analysis)
    parts << (capabilities.any? ? capabilities.join(" / ") : "該当する攻撃能力なし")
    parts.join(" ／ ")
  end

  def change_description(change)
    case change["type"]
    when "result"
      if change["from"].nil?
        "#{judgement_label(change['to'])} と判定した"
      else
        "判定が #{judgement_label(change['from'])} から #{judgement_label(change['to'])} に変わった"
      end
    when "selected_assessment"
      from, to = change.values_at("from", "to").map { |a| a && assessment_origin(a["source"], a["version"]) }
      if from.nil? then "採用評価として #{to} の評価が付いた"
      elsif to.nil? then "採用評価（#{from}）が無くなった"
      else "採用評価が #{from} から #{to} に変わった"
      end
    when "assessment"
      "#{assessment_origin(change['source'], change['version'])} の評価で #{change['field']} が #{change['from']} から #{change['to']} に変わった"
    when "capability"
      "攻撃能力「#{CAPABILITY_LABELS.fetch(change['capability'], change['capability'])}」が " \
        "#{TRI_STATE_LABELS.fetch(change['from'].to_s, '-')} から #{TRI_STATE_LABELS.fetch(change['to'].to_s, '-')} に変わった"
    else
      change.to_json
    end
  end

  def format_time(time)
    time&.in_time_zone("Asia/Tokyo")&.strftime("%Y-%m-%d %H:%M")
  end
end
