require "net/http"

# Calls the OpenAI Responses API with a JSON schema (structured output).
class OpenaiClient
  class Error < StandardError; end

  ENDPOINT = URI("https://api.openai.com/v1/responses")
  NETWORK_ERRORS = [ Timeout::Error, SocketError, SystemCallError, IOError, OpenSSL::SSL::SSLError ].freeze

  Response = Data.define(:output, :raw)

  attr_reader :model

  def initialize(api_key: ENV["OPENAI_API_KEY"], model: ENV["OPENAI_MODEL"], timeout: ENV.fetch("OPENAI_TIMEOUT", 60).to_i)
    @api_key = api_key
    @model = model
    @timeout = timeout
  end

  def configured?
    @api_key.present? && model.present?
  end

  # Returns a Response whose output is the parsed JSON object conforming to schema.
  def structured_output(instructions:, input:, schema_name:, schema:)
    raw = post(
      model:,
      instructions:,
      input:,
      text: { format: { type: "json_schema", name: schema_name, schema:, strict: true } }
    )
    text = Array(raw["output"]).flat_map { |item| Array(item["content"]) }.find { |c| c["type"] == "output_text" }&.dig("text")
    raise Error, "OpenAI returned no output (status: #{raw['status']})" if text.nil?

    Response.new(output: JSON.parse(text), raw:)
  rescue JSON::ParserError => error
    raise Error, "OpenAI returned invalid JSON: #{error.message}"
  end

  private
    def post(body)
      http = Net::HTTP.new(ENDPOINT.host, ENDPOINT.port)
      http.use_ssl = true
      http.open_timeout = @timeout
      http.read_timeout = @timeout

      request = Net::HTTP::Post.new(ENDPOINT, "Authorization" => "Bearer #{@api_key}", "Content-Type" => "application/json")
      request.body = JSON.generate(body)
      response = http.request(request)
      raise Error, "OpenAI API #{response.code}: #{response.body.to_s.truncate(500)}" unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(response.body)
    rescue *NETWORK_ERRORS => error
      raise Error, "OpenAI API request failed: #{error.class}: #{error.message}"
    end
end
