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
        uint16              :structure_size,           label: 'Structure Size', initial_value: 36
        uint16              :dialect_count,            label: 'Dialect Count', initial_value: -> { dialects.size }
        smb2_security_mode  :security_mode,            label: 'Security Mode'
        uint16              :reserved1,                label: 'Reserved', initial_value: 0
        smb2_capabilities   :capabilities,             label: 'Capabilities'
        string              :client_guid,              label: 'Client GUID', length: 16
        struct              :negotiate_context_info,   label: 'Negotiate Context Info', onlyif: -> { has_negotiate_context? } do
          uint32            :negotiate_context_offset, label: 'Negotiate Context Offset', initial_value: -> { negotiate_context_list.abs_offset }
          uint16            :negotiate_context_count,  label: 'Negotiate Context Count', initial_value: -> { negotiate_context_list.size }
          uint16            :reserved2,                label: 'Reserved', initial_value: 0
        end
        file_time           :client_start_time,        label: 'Client Start Time', initial_value: 0, onlyif: -> { !has_negotiate_context? }
        array               :dialects,                 label: 'Dialects', type: :uint16, initial_length: -> { dialect_count }
        string              :pad,                      label: 'Padding', length: -> { pad_length(self.dialects) }, onlyif: -> { has_negotiate_context? }
        array               :negotiate_context_list,   label: 'Negotiate Context List', type: :negotiate_context, onlyif: -> { has_negotiate_context? }, read_until: :eof

        # Adds a dialect to the Dialects array
        #
        # @param [Integer] the numeric code for the dialect you wish to add
        # @return [Array<Integer>] the array of all currently selected dialects
        # @raise [ArgumentError] if the dialect is not an Integer
        def add_dialect(dialect)
          raise ArgumentError, 'Must be a number' unless dialect.is_a? Integer
          self.dialects << dialect
        end

        # Takes an array of dialects and sets it on the packet. Also updates
        # the dialect_count field appropriately. Will erase any previously set
        # dialects.
        #
        # @param [Array<Integer>] the array of dialects to set
        # @return [Array<Integer>] the current value of the dialects array
        def set_dialects(add_dialects = [])
          self.dialects = []
          add_dialects.each do |dialect|
            add_dialect(dialect)
          end
          dialects
        end

        # Adds a Negotiate Context to the #negotiate_context_list
        #
        # @param [NegotiateContext] the Negotiate Context structure you wish to add
        # @return [Array<Integer>] the array of all currently added Negotiate Contexts
        # @raise [ArgumentError] if the dialect is not a NegotiateContext structure
        def add_negotiate_context(nc)
          raise ArgumentError, 'Must be a NegotiateContext' unless nc.is_a? NegotiateContext
          previous_element = negotiate_context_list.last || negotiate_context_list
          pad_length = pad_length(previous_element)
          self.negotiate_context_list << nc
          self.negotiate_context_list.last.pad = "\x00" * pad_length
          self.negotiate_context_list
        end

        # Find the first Negotiate Context structure that matches the given
        # context type
        #
        # @param [Integer] the Negotiate Context structure you wish to add
        # @return [NegotiateContext] the Negotiate Context structure or nil if
        # not found
        def find_negotiate_context(type)
          negotiate_context_list.find { |nc| nc.context_type == type }
        end

        private

        # Determines the correct length for the padding, so that the next
        # field is 8-byte aligned.
        def pad_length(prev_element)
          offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 8
          (8 - offset) % 8
        end

        # Return true if the dialect version requires Negotiate Contexts
        def has_negotiate_context?
          dialects.any? { |dialect| dialect.to_i == 0x0311 }
        end
      end
    end
  end
end
