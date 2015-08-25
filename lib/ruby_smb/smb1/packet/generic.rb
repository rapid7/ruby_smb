module RubySMB
  module SMB1
    module Packet
      # Parent class for all SMB1 Packets.
      class Generic < BinData::Record
        smb_header :smb_header

        def self.describe
          description = ''
          fields.each do |field|
            section_string = field.name.to_s.upcase
            sub_fields = field.prototype.instance_variable_get(:@obj_params)[:fields].fields
            sub_fields.each do |sub_field|
              section_string << formatted_sub_field(sub_field)
            end
            description << "#{section_string}\n"
          end
          description
        end

        def self.formatted_class(prototype)
          obj_class = prototype.instance_variable_get(:@obj_class).to_s
          obj_class.split('::').last
        end

        def self.formatted_label(prototype)
          params = prototype.instance_variable_get(:@obj_params)
          params[:label] || ''
        end

        def self.formatted_sub_field(sub_field)
          sub_field_prototype = sub_field.prototype
          sub_field_class = self.formatted_class(sub_field_prototype)
          sub_field_label = self.formatted_label(sub_field_prototype)
          sprintf "\n\t%-20s %-10s %s", sub_field.name.capitalize, sub_field_class, sub_field_label
        end


      end
    end
  end
end