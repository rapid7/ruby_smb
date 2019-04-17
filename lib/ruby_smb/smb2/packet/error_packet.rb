module RubySMB
  module SMB2
    module Packet
      # This class represents an SMB2 Error Response Packet as defined in
      # [2.2.2 SMB2 ERROR Response](https://msdn.microsoft.com/en-us/library/cc246530.aspx)
      class ErrorPacket < RubySMB::GenericPacket
        attr_accessor :original_command

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size,      label: 'Structure Size', initial_value: 9
        uint8        :error_context_count, label: 'ErrorContextCount'
        uint8        :reserved
        uint32       :byte_count,          label: 'Byte Count of ErrorData'
        string       :error_data,          label: 'Error Data', read_length: -> { byte_count }

        def valid?
          return smb2_header.protocol == RubySMB::SMB2::SMB2_PROTOCOL_ID &&
                 smb2_header.command == @original_command &&
                 structure_size == 9
        end
      end
    end
  end
end
