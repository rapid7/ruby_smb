module RubySMB
  module SMB1
    module Packet
      class DataBlock < BinData::Record
        endian  :little

        uint16   :byte_count,  :value => lambda { calculate_byte_count }

        def calculate_byte_count
          total_count = 0
          self.class.data_fields.each do |field_name|
            field_value = self.send(field_name)
            total_count += field_value.do_num_bytes
          end
          total_count
        end

        def self.data_fields
          fields = self.fields.collect { |field| field.name }
          fields.reject { |field| field == :byte_count }
        end

      end
    end
  end
end