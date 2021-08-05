module RubySMB
  module Dialect
    # the order (taxonomic ranking) of the family, 2 and 3 are intentionally combined
    ORDER_SMB1 = 'SMB1'.freeze
    ORDER_SMB2 = 'SMB2'.freeze

    # the family of the dialect
    FAMILY_SMB1 = 'SMB 1'.freeze
    FAMILY_SMB2 = 'SMB 2.x'.freeze
    FAMILY_SMB3 = 'SMB 3.x'.freeze

    # the major version of the dialect
    VERSION_SMB1 = 'SMB v1'.freeze
    VERSION_SMB2 = 'SMB v2'.freeze
    VERSION_SMB3 = 'SMB v3'.freeze

    # the names are meant to be human readable and may change in the future, use the #dialect, #order and #family
    # attributes for any programmatic comparisons
    Definition = Struct.new(:dialect, :order, :family, :version_name, :full_name) do
      alias :short_name :version_name
    end

    ALL = [
      Definition.new('NT LM 0.12', ORDER_SMB1, FAMILY_SMB1, VERSION_SMB1, 'SMB v1 (NT LM 0.12)'.freeze),
      Definition.new('0x0202',     ORDER_SMB2, FAMILY_SMB2, VERSION_SMB2, 'SMB v2.0.2'.freeze),
      Definition.new('0x0210',     ORDER_SMB2, FAMILY_SMB2, VERSION_SMB2, 'SMB v2.1'.freeze),
      Definition.new('0x0300',     ORDER_SMB2, FAMILY_SMB3, VERSION_SMB3, 'SMB v3.0'.freeze),
      Definition.new('0x0302',     ORDER_SMB2, FAMILY_SMB3, VERSION_SMB3, 'SMB v3.0.2'.freeze),
      Definition.new('0x0311',     ORDER_SMB2, FAMILY_SMB3, VERSION_SMB3, 'SMB v3.1.1'.freeze)
    ].map { |definition| [definition.dialect, definition] }.to_h

    def self.[](dialect)
      dialect = "0x%04x" % dialect if dialect.is_a? Integer
      ALL[dialect]
    end
  end
end
