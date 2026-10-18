# Asks OpenAI, in a single call, for the attack capabilities and Japanese summary.
#
# OpenAI is called only when the AI input's hash differs from every earlier analysis of the CVE.
class CveAnalyzer
  PROMPT_VERSION = "2026-10-15".freeze

  CAPABILITIES = AiAnalysis::CAPABILITIES.map(&:to_s).freeze
  TRI_STATE = { type: "string", enum: AiAnalysis::TRI_STATE }.freeze
  SUMMARY_FIELDS = %w[overview impact affected mitigation].freeze

  SCHEMA = {
    type: "object",
    additionalProperties: false,
    required: %w[capabilities evidence summary],
    properties: {
      capabilities: {
        type: "object",
        additionalProperties: false,
        required: CAPABILITIES,
        properties: CAPABILITIES.index_with { TRI_STATE }
      },
      evidence: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          required: %w[capability source quote],
          properties: {
            capability: { type: "string", enum: CAPABILITIES },
            source: { type: "string" },
            quote: { type: "string" }
          }
        }
      },
      summary: {
        type: "object",
        additionalProperties: false,
        required: SUMMARY_FIELDS,
        properties: SUMMARY_FIELDS.index_with { { type: "string" } }
      }
    }
  }.freeze

  INSTRUCTIONS = <<~PROMPT.freeze
    あなたは脆弱性情報を分析するセキュリティアナリストです。
    入力は CVE レコードから抜き出した JSON です。
    - title: CNA（CVE を登録した組織）が付けた表題（無い場合あり）
    - descriptions: CNA の説明文
    - configurations: 脆弱性が該当する設定条件（無い場合あり）
    - affected: 影響を受ける製品・バージョン
    - cvss: CNA と CISA-ADP の CVSS 評価（ベクトル文字列）

    入力に書かれていることだけを根拠にし、推測で補わないでください。

    1. capabilities: この脆弱性を突いた攻撃者が、攻撃に成功したときに得られる結果を、次の 4 種それぞれについて "true" / "false" / "unknown" で答えてください。
       - remote_code_execution: 遠隔から任意のコードを実行できる
       - authentication_bypass: ログイン等の認証を経ずに保護された機能へ到達できる
       - shell_access: 対象サーバー上でコマンドを打てる状態になる
       - root_access: 対象サーバーの最上位権限（root）を得る
       入力から明確に読み取れる場合だけ "true"、明確に否定できる場合（影響が情報漏えいやサービス停止に限られると読み取れる等）は "false"、どちらとも決められなければ "unknown" にしてください。
    2. evidence: "true" または "false" と答えた攻撃能力ごとに、根拠の出所（例:「CNA の説明文」「CNA の CVSS 評価」）と、入力中の該当箇所を原文のまま引用してください。
    3. summary: 日本語の要約です。全訳ではなく、簡潔にまとめてください。
       - overview: 何が原因の脆弱性か
       - impact: 攻撃者が何をできるか
       - affected: 影響を受ける製品・バージョン
       - mitigation: 修正版・回避策（入力に記載が無ければ「記載なし」）
  PROMPT

  def initialize(client: OpenaiClient.new, logger: Rails.logger)
    @client = client
    @logger = logger
  end

  # Returns the AiAnalysis for the CVE's current AI input, or nil when OpenAI is not configured.
  # Raises OpenaiClient::Error when the call fails.
  def analyze(cve)
    return unless cve.analysis_eligible?

    input = AiInput.for(cve)
    input_hash = input.digest

    previous = cve.ai_analyses.where(input_hash:).order(:analyzed_at, :id).last
    return previous if previous

    unless @client.configured?
      @logger.warn("[analyzer] OPENAI_API_KEY / OPENAI_MODEL are not set; skipping #{cve.identifier}")
      return
    end

    response = @client.structured_output(
      instructions: INSTRUCTIONS,
      input: JSON.pretty_generate(input.to_h),
      schema_name: "cve_analysis",
      schema: SCHEMA
    )
    store(cve, input, input_hash, response)
  end

  private
    def store(cve, input, input_hash, response)
      output = response.output
      summary = output.fetch("summary")

      cve.ai_analyses.create!(
        input: input.to_h,
        input_hash:,
        model: @client.model,
        prompt_version: PROMPT_VERSION,
        analyzed_at: Time.current,
        **output.fetch("capabilities").slice(*CAPABILITIES).symbolize_keys,
        evidence: output.fetch("evidence"),
        summary_overview: summary["overview"],
        summary_impact: summary["impact"],
        summary_affected: summary["affected"],
        summary_mitigation: summary["mitigation"],
        raw_response: response.raw
      )
    end
end
