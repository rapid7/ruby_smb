module RubySMB
  module SMB2
    module Packet
      # An SMB2 Error packet for when an incomplete response comes back
      class ErrorPacket < RubySMB::GenericPacket
        attr_accessor :original_command

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 4
        uint8        :error_data

        def valid?
          return smb2_header.protocol == RubySMB::SMB2::SMB2_PROTOCOL_ID &&
            smb2_header.command == @original_command
        end
      end
    end
  end
end
