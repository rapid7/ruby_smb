module RubySMB
  module SMB1
    module Packet
      module Trans2
        # SET_FS Information Levels used in TRANS2_SET_FS_INFORMATION.
        #
        # MS-CIFS marks the parent subcommand
        # [TRANS2_SET_FS_INFORMATION (0x0004)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/ac4b00db-6015-416a-89a1-bf5da2503bc3)
        # as "reserved but not implemented" — the info level codes below are
        # defined by the CIFS UNIX Extensions draft maintained by the Samba
        # team and implemented in
        # [source3/smbd/smb1_trans2.c](https://github.com/samba-team/samba/blob/master/source3/smbd/smb1_trans2.c).
        # They sit in the 0x0200–0x02FF range reserved by
        # [MS-CIFS 2.2.2.3 Information Level Codes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/03c10ab9-d723-4368-b9a6-c72de3244c77)
        # for third-party extensions.
        module SetFsInformationLevel
          # Client advertises / negotiates CIFS UNIX Extensions support.
          # Data block: major:u16, minor:u16, capabilities:u64.
          SMB_SET_CIFS_UNIX_INFO = 0x0200

          def self.name(value)
            constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
          end
        end
      end
    end
  end
end
