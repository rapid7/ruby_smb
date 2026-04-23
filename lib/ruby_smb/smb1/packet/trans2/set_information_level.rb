module RubySMB
  module SMB1
    module Packet
      module Trans2
        # Information Level codes valid for Trans2 SET_PATH_INFORMATION and
        # SET_FILE_INFORMATION requests.
        #
        # FSCC pass-through levels are defined in
        # {RubySMB::Fscc::FileInformation} and require
        # `SMB_INFO_PASSTHROUGH` to be added. The constants defined here are
        # the CIFS UNIX Extensions info levels used by Samba servers that
        # advertise UNIX extensions support in their negotiate response.
        #
        # See [SNIA CIFS Technical Reference, Appendix F: CIFS UNIX Extensions]
        # (https://www.snia.org/sites/default/files/CIFS-TR-1p00_FINAL.pdf).
        module SetInformationLevel
          # Set the symbolic link target for a file. The Trans2 parameters
          # block carries the path being created (the symlink itself); the
          # Trans2 data block carries the target path as a null-terminated
          # string.
          SMB_SET_FILE_UNIX_LINK = 0x0201

          # Create a hard link. Data block carries the existing file path.
          SMB_SET_FILE_UNIX_HLINK = 0x0203

          def self.name(value)
            constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
          end
        end
      end
    end
  end
end
