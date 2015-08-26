module RubySMB
  module SMB1
    module Packet
      # Parent class for all SMB1 Packets.
      class Generic < BinData::Record
        smb_header :smb_header

        # Outputs a nicely formatted string representation
        # of the Packet's structure.
        #
        # @return [String] formatted string representation of the packet structure
        def self.describe
          description = ''
          fields_hashed.each do |field|
            description << self.format_field(field)
          end
          description
        end


        def display
          display_str = ''
          self.class.fields.each do |field|
            section_string = field.name.to_s.upcase
            sub_fields = field.prototype.instance_variable_get(:@obj_params)[:fields].fields
            sub_fields.each do |sub_field|
              name = sub_field.name
              value = self.send(field.name).send(name)
              label = self.class.formatted_label(sub_field.prototype)
              field_str = ''
              if label.empty?
                field_str = sprintf "\n\t%-20s %s", name.capitalize, value
              else
                field_str = sprintf "\n\t%-20s %s", label, value
              end
              section_string << field_str
            end
            display_str << "#{section_string}\n"
          end
          display_str
        end

        private

        # Returns an array of hashes representing the
        # fields for this record.
        #
        # @return [Array<Hash>] the array of hash representations of the record's fields
        def self.fields_hashed
          walk_fields(self.fields)
        end

        # Takes a hash representation of a field and spits out a formatted
        # string representation.
        #
        # @param field [Hash] the hash representing the field
        # @param depth [Fixnum] the recursive depth level to track indentation
        # @return [String] the formatted string representation of the field
        def self.format_field(field,depth=0)
          name = field[:name].to_s
          if field[:class].ancestors.include? BinData::Record
            class_str = ''
            name.upcase!
          else
            class_str = field[:class].to_s.split('::').last
            class_str = "(#{class_str})"
            name.capitalize!
          end
          formatted_name = "\n" + ("\t" * depth) + name
          formatted_string = sprintf "%-20s %-10s %s", formatted_name, class_str, field[:label]
          field[:fields].each do |sub_field|
            formatted_string << self.format_field(sub_field,(depth+1))
          end
          formatted_string
        end

        # Recursively walks through a field, building a hash representation
        # of that field and all of it's sub-fields.
        #
        # @param fields [Array<BinData::SanitizedField>] an array of fields to walk
        # @return [Array<Hash>] an array of hashes representing the fields
        def self.walk_fields(fields)
          field_hashes = []
          fields.each do |field|
            field_hash = {}
            field_hash[:name] = field.name
            prototype = field.prototype
            field_hash[:class] = prototype.instance_variable_get(:@obj_class)
            params =  prototype.instance_variable_get(:@obj_params)
            field_hash[:label] = params[:label]
            field_hash[:value] = params[:value]
            sub_fields = params[:fields]
            if sub_fields.nil?
              field_hash[:fields] = []
            else
              field_hash[:fields] = self.walk_fields(sub_fields)
            end
            field_hashes << field_hash
          end
          field_hashes
        end

      end
    end
  end
end