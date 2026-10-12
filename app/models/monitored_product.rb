# A product listed in config/monitored_products.yml.
class MonitoredProduct
  CONFIG_PATH = Rails.root.join("config/monitored_products.yml")

  attr_reader :name, :vendors, :aliases

  def self.all(path = CONFIG_PATH)
    YAML.safe_load_file(path).fetch("products").map do |attrs|
      new(name: attrs.fetch("name"), vendors: attrs["vendors"], aliases: attrs["aliases"])
    end
  end

  def initialize(name:, vendors: nil, aliases: nil)
    @name = name
    @vendors = Array(vendors)
    @aliases = Array(aliases)
  end

  # Terms compared against affected[].vendor / product (strength 1).
  def primary_terms
    ([ name ] + vendors).map(&:downcase).uniq
  end

  # Terms compared against affected[].product (strength 2).
  def alias_terms
    aliases.map(&:downcase).uniq - primary_terms
  end

  # Terms compared against descriptions (strength 3).
  def description_terms
    ([ name ] + aliases).map(&:downcase).uniq
  end

  def all_terms
    (primary_terms + alias_terms + description_terms).uniq
  end
end
