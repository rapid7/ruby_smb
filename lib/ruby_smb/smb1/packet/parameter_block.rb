module RubySMB
  module SMB1
    module Packet
      class ParameterBlock < BinData::Record
        endian  :little

        uint8   :word_count,  :value => lambda { calculate_word_count }

        def calculate_word_count
          total_count = 0
          self.class.parameter_fields.each do |field_name|
            field_value = self.send(field_name)
            total_count += field_value.do_num_bytes / 2
          end
          total_count
        end

        def self.parameter_fields
          fields = self.fields.collect { |field| field.name }
          fields.reject { |field| field == :word_count }
        end

      end
    end
  end
end