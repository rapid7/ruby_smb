module RubySMB
  module Nbss
    # Representation of the NetBIOS Session Service Header as defined in
    # SMB: [2.1 Transport](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/f906c680-330c-43ae-9a71-f854e24aeee6)
    # SMB2: [2.1 Transport](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1dfacde4-b5c7-4494-8a14-a09d3ab4cc83)
    class SessionHeader < BinData::Record
      endian :big

      uint8  :session_packet_type,    label: 'Session Packet Type', initial_value: 0
      uint24 :stream_protocol_length, label: 'Stream Protocol Length'
    end
  end
end
