module RubySMB
  module SMB1
    module Packet
      module Trans2
        # Information Level codes valid for Trans2 SET_PATH_INFORMATION and
        # SET_FILE_INFORMATION requests. See
        # [MS-CIFS 2.2.2.3.4 SET Information Level Codes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/0321265e-312a-4721-90fa-cd40a443ed86).
        #
        # FSCC pass-through levels are defined in
        # {RubySMB::Fscc::FileInformation} and require
        # `SMB_INFO_PASSTHROUGH` to be added. The constants defined here are
        # the CIFS UNIX Extensions info levels used by Samba servers that
        # advertise UNIX extensions support in their negotiate response. These
        # levels fall outside MS-CIFS; their wire format is defined by the
        # CIFS UNIX Extensions draft and implemented by Samba — see
        # [source3/smbd/smb1_trans2.c](https://github.com/samba-team/samba/blob/master/source3/smbd/smb1_trans2.c).
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
