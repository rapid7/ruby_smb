require 'ruby_smb/smb2/negotiate_context'

module RubySMB
  module SMB2
    module Packet
      # An SMB2 NEGOTIATE Response packet as defined by
      # [2.2.4 SMB2 NEGOTIATE Response](https://msdn.microsoft.com/en-us/library/cc246561.aspx)
      class NegotiateResponse < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::NEGOTIATE

        endian              :little
        smb2_header         :smb2_header
        uint16              :structure_size,            label: 'Structure Size', initial_value: 65
        smb2_security_mode  :security_mode
        uint16              :dialect_revision,          label: 'Dialect Revision'
        uint16              :negotiate_context_count,   label: 'Negotiate Context Count', initial_value: -> { negotiate_context_list.size }, onlyif: -> { has_negotiate_context? }
        uint16              :reserved1,                 label: 'Reserved', initial_value: 0, onlyif: -> { !has_negotiate_context? }
        string              :server_guid,               label: 'Server GUID', length: 16
        smb2_capabilities   :capabilities
        uint32              :max_transact_size,         label: 'Max Transaction Size'
        uint32              :max_read_size,             label: 'Max Read Size'
        uint32              :max_write_size,            label: 'Max Write Size'
        file_time           :system_time,               label: 'Server System Time'
        file_time           :server_start_time,         label: 'Server Start Time'
        uint16              :security_buffer_offset,    label: 'Offset to Security Buffer'
        uint16              :security_buffer_length,    label: 'Security Buffer Length', initial_value: -> { security_buffer.length }
        uint32              :negotiate_context_offset,  label: 'Offset to Negotiate Context', onlyif: -> { has_negotiate_context? }
        uint32              :reserved2,                 label: 'Reserved', initial_value: 0, onlyif: -> { !has_negotiate_context? }
        string              :security_buffer,           label: 'Security Buffer', read_length: :security_buffer_length
        string              :pad,                       label: 'Padding', length: -> { pad_length(self.security_buffer) }, onlyif: -> { has_negotiate_context? }
        array               :negotiate_context_list,    label: 'Negotiate Context List', initial_length: -> { negotiate_context_count }, type: :negotiate_context, onlyif: -> { has_negotiate_context? }

        def initialize_instance
          super
          smb2_header.flags.reply = 1
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

        # Adds a Negotiate Context to the #negotiate_context_list
        #
        # @param [NegotiateContext] the Negotiate Context structure you wish to add
        # @return [Array<Fixnum>] the array of all currently added Negotiate Contexts
        # @raise [ArgumentError] if the dialect is not a NegotiateContext structure
        def add_negotiate_context(nc)
          raise ArgumentError, 'Must be a NegotiateContext' unless nc.is_a? NegotiateContext
          previous_element = negotiate_context_list.last || negotiate_context_list
          pad_length = pad_length(previous_element)
          self.negotiate_context_list << nc
          self.negotiate_context_list.last.pad = "\x00" * pad_length
          self.negotiate_context_list
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
          dialect_revision == 0x0311
        end

      end
    end
  end
end
