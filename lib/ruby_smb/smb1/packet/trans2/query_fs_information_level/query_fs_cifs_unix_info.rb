module RubySMB
  module SMB1
    module Packet
      module Trans2
        module QueryFsInformationLevel
          # Response data for SMB_QUERY_CIFS_UNIX_INFO (0x0200) from the
          # CIFS UNIX Extensions. 12 bytes: major/minor version pair plus
          # a 64-bit capability bitfield that the client echoes back in
          # SMB_SET_CIFS_UNIX_INFO to enable UNIX extensions for the session.
          #
          # Outside of MS-CIFS; wire format defined by the CIFS UNIX
          # Extensions draft maintained by the Samba team. The parent
          # subcommand is documented at
          # [MS-CIFS 2.2.6.4 TRANS2_QUERY_FS_INFORMATION (0x0003)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/a96c1c03-cade-4a4a-81a9-b00674d23d93);
          # the CIFS UNIX Info layout is implemented in
          # [source3/smbd/smb1_trans2.c](https://github.com/samba-team/samba/blob/master/source3/smbd/smb1_trans2.c).
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
