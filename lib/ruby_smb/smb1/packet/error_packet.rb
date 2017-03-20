module RubySMB
  module SMB1
    module Packet

      # This packet rpresent an SMB1 Response Packet when an Error has occured.
      # The Parameter and Data Blocks will be empty, for reasons.
      class ErrorPacket < RubySMB::GenericPacket
        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block
      end
    end
  end
end