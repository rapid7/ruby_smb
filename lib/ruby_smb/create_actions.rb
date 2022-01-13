module RubySMB
  # This module holds the Create Actions used in NT_TRANSACT_CREATE,
  # SMB_COM_NT_CREATE_ANDX, and SMB2_CREATE responses. The definitions for these
  # values can be found at
  # [2.2.7.1.2 Response](https://msdn.microsoft.com/en-us/library/ee441961.aspx)
  # and
  # [2.2.14 SMB2 CREATE Response](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d166aa9e-0b53-410e-b35e-3933d8131927)
  module CreateActions
    # An existing file was deleted and a new file was created in its place.
    FILE_SUPERSEDED = 0x00000000

    # An existing file was opened.
    FILE_OPENED = 0x00000001

    # A new file was created.
    FILE_CREATED = 0x00000002

    # An existing file was overwritten.
    FILE_OVERWRITTEN = 0x00000003
  end
end
