require 'pry'
module RubySMB
  module SMB1
    # Base model for all requests + responses
    class SMBPacket < BinData::Record
      endian  :little

      # SMBHeader
      bit32   :protocol_field, :value => RubySMB::SMB1::SMB_PROTOCOL_ID
      bit8    :command_field
      bit32   :nt_status_field
      bit8    :flags_field
      bit16   :flags2_field
      bit16   :pid_high_field
      bit64   :security_features_field
      bit16   :reserved_field
      bit16   :tid_field
      bit16   :pid_low_field
      bit16   :uid_field
      bit16   :mid_field

      # SMBParameterBlock
      uint8   :word_count_field,  :value => lambda { (words_field.force_encoding('binary').length / 2.0).ceil }
      string  :words_field,       :read_length => lambda { word_count_field * 2 }

      # SMBDataBlock
      uint16  :byte_count_field,  :value => lambda { bytes_field.length }
      string  :bytes_field,       :read_length => :byte_count

      # Define setter/getter methods for each field
      self.fields.map(&:name).each do |field_name|
        define_method(field_name.to_s.split('_field').first) do
          send(field_name)
        end

        define_method(field_name.to_s.split('_field').first + '=') do |value|
          send(field_name.to_s + '=', value)
        end
      end

      def bytes=(value)
        raise ArgumentError, "value must be a binary string" unless value.kind_of? String
        self.bytes_field = value
      end

      def words=(value)
        raise ArgumentError, "value must be a binary string" unless value.kind_of? String
        self.words_field = value
      end

      def inspect_detailed
        string = ""
        packet_fields.each do |field|
          string += "#{field}: #{send(field)}\n"
        end
        print string
      end

      private

      #Returns fields of the SMBPacket
      def packet_fields
        if self.respond_to?('fields')
          self.fields.map{|field_name| stripped_name(field_name.name) }
        else
          self.field_names.map{ |field_name| stripped_name(field_name) }
        end
      end

      #Strips the _field from the BinData field names
      def stripped_name(full_field_name)
        full_field_name.to_s.split('_field').first
      end
    end
  end
end