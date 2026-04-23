module RubySMB
  module SMB1
    module Packet
      module Trans2
        module QueryFsInformationLevel
          # Response data for SMB_QUERY_CIFS_UNIX_INFO (0x0200) from the
          # CIFS UNIX Extensions. 12 bytes: major/minor version pair plus
          # a 64-bit capability bitfield that the client echoes back in
          # SMB_SET_CIFS_UNIX_INFO to enable UNIX extensions for the session.
          class QueryFsCifsUnixInfo < BinData::Record
            endian :little

            uint16 :major_version, label: 'Major Version'
            uint16 :minor_version, label: 'Minor Version'
            uint64 :capabilities,  label: 'Capabilities'
          end
        end
      end
    end
  end
end
