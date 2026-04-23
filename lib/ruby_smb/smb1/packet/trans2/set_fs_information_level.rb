module RubySMB
  module SMB1
    module Packet
      module Trans2
        # SET_FS Information Levels used in TRANS2_SET_FS_INFORMATION.
        # These are not defined in [MS-CIFS] because they were added
        # through the CIFS UNIX Extensions draft maintained by the
        # Samba team. See [SNIA CIFS Technical Reference, Appendix F].
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
