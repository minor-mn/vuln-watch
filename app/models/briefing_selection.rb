class BriefingSelection
  attr_reader :hours, :limit, :now, :since

  def initialize(hours: nil, limit: nil, now: Time.current)
    @custom = !hours.nil? || !limit.nil?
    @hours = hours.nil? ? 24.0 : parse_hours(hours)
    @limit = limit.nil? ? nil : parse_limit(limit)
    @now = now
    @since = now - @hours.hours
    raise ArgumentError, "hours is outside the supported time range" unless @since.year.between?(1, 9999)
  rescue RangeError
    raise ArgumentError, "hours is outside the supported time range"
  end

  def custom?
    @custom
  end

  # Callers provide a newest-first scope. Explicit conditions never add older rows.
  def apply(scope, date:)
    eligible = scope.where(date => ..now)
    recent = eligible.where(date => since..now)
    return limit ? recent.limit(limit) : recent if custom?

    recent.count >= 5 ? recent : eligible.limit(5)
  end

  def policy
    custom? ? "per_source_window" : "per_source_24h_or_latest_5"
  end

  private
    def parse_hours(value)
      hours = Float(value)
      raise ArgumentError unless hours.finite? && hours.positive?
      hours
    rescue ArgumentError, TypeError
      raise ArgumentError, "hours must be a positive finite number"
    end

    def parse_limit(value)
      raise ArgumentError unless (value.is_a?(String) || value.is_a?(Integer)) && value.to_s.match?(/\A[0-9]+\z/)
      limit = value.to_i
      raise ArgumentError unless limit.between?(1, 2**63 - 1)
      limit
    rescue ArgumentError
      raise ArgumentError, "limit must be a positive 64-bit integer"
    end
end
