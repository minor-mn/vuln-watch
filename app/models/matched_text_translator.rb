# Translates the matched_text of a CVE's product matches into Japanese with OpenAI, one call per
# CVE for the matches not yet translated.
class MatchedTextTranslator
  SCHEMA = {
    type: "object",
    additionalProperties: false,
    required: %w[translations],
    properties: {
      translations: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          required: %w[id japanese],
          properties: { id: { type: "integer" }, japanese: { type: "string" } }
        }
      }
    }
  }.freeze

  INSTRUCTIONS = <<~PROMPT.freeze
    入力は CVE レコードから抜き出した英語のテキストの配列です（各要素は id と text）。
    各 text を自然な日本語に訳し、同じ id と組にして translations に入れてください。
    製品名・ベンダー名・バージョン番号・コマンドや設定の記述は原文のまま残してください。
    製品名だけのテキストなど、訳す部分が無い場合は原文をそのまま返してください。
  PROMPT

  def initialize(client: OpenaiClient.new, logger: Rails.logger)
    @client = client
    @logger = logger
  end

  # Raises OpenaiClient::Error when the call fails.
  def translate(cve)
    matches = cve.product_matches.untranslated.to_a
    return if matches.empty?

    unless @client.configured?
      @logger.warn("[translator] OPENAI_API_KEY / OPENAI_MODEL are not set; skipping #{cve.identifier}")
      return
    end

    response = @client.structured_output(
      instructions: INSTRUCTIONS,
      input: JSON.pretty_generate(matches.map { |match| { id: match.id, text: match.matched_text } }),
      schema_name: "matched_text_translation",
      schema: SCHEMA
    )
    by_id = response.output.fetch("translations").to_h { |t| [ t["id"], t["japanese"] ] }

    ProductMatch.transaction do
      matches.each do |match|
        japanese = by_id[match.id]
        match.update!(matched_text_ja: japanese) if japanese.present?
      end
    end
  end
end
