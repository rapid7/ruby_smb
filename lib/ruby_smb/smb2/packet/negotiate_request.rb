require 'ruby_smb/smb2/negotiate_context'

module RubySMB
  module SMB2
    module Packet
      # An SMB2 NEGOTIATE Request packet as defined by
      # [2.2.3 SMB2 NEGOTIATE Request](https://msdn.microsoft.com/en-us/library/cc246543.aspx)
      class NegotiateRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::NEGOTIATE

        endian              :little
        smb2_header         :smb2_header
        uint16              :structure_size,         label: 'Structure Size', initial_value: 36
        uint16              :dialect_count,          label: 'Dialect Count', initial_value: -> { dialects.size }
        smb2_security_mode  :security_mode
        uint16              :reserved1, label: 'Re   served', initial_value: 0
        smb2_capabilities   :capabilities
        string              :client_guid,            label: 'Client GUID',        length: 16
        struct              :negotiate_context_info, label: 'Negotiate Context Info', onlyif: -> { need_negotiate_context? } do
          uint32            :negotiate_context_offset, label: 'Negotiate Context Offset', initial_value: -> { negotiate_context_list.abs_offset }
          uint16            :negotiate_context_count,  label: 'Negotiate Context Count',  initial_value: -> { negotiate_context_list.size }
          uint16            :reserved2,                label: 'Reserved',                 initial_value: 0
        end
        file_time           :client_start_time,      label: 'Client Start Time',  initial_value: 0, onlyif: -> { !need_negotiate_context? }
        array               :dialects,               label: 'Dialects', type: :uint16, initial_length: -> { dialect_count }
        string              :pad,                    label: 'Padding', length: -> { pad_length }, onlyif: -> { need_negotiate_context? }
        array               :negotiate_context_list, label: 'Negotiate Context List', type: :negotiate_context, onlyif: -> { need_negotiate_context? }

        # Adds a dialect to the Dialects array and increments the dialect count
        #
        # @param [Fixnum] the numeric code for the dialect you wish to add
        # @return [Array<Fixnum>] the array of all currently selected dialects
        def add_dialect(dialect)
          return ArgumentError, 'Must be a number' unless dialect.is_a? Integer
          self.dialects << dialect
        end

        # Takes an array of dialects and sets it on the packet. Also updates
        # the dialect_count field appropriately. Will erase any previously set
        # dialects.
        #
        # @param [Array<Fixnum>] the array of dialects to set
        # @return [Array<Fixnum>] the current value of the dialects array
        def set_dialects(add_dialects = [])
          self.dialects = []
          self.dialect_count = 0
          add_dialects.each do |dialect|
            add_dialect(dialect)
          end
          dialects
        end

        private

        # Determines the correct length for the padding between the #dialects
        # array and the first negotiate context, so that the first negotiate
        # context is 8-byte aligned.
        def pad_length
          offset = (dialects.abs_offset + dialects.to_binary_s.length) % 8
          (8 - offset) % 8
        end

        def need_negotiate_context?
          dialects.any? { |dialect| dialect.to_i == 0x0311 }
        end
      end
    end
  end
end
