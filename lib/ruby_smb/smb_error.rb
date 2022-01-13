require 'windows_error'

module RubySMB
  # SMB Error codes as defined in
  # [2.2.2.4 SMB Error Classes and Codes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/6ab6ca20-b404-41fd-b91a-2ed39e3762ea)
  module SMBError
    # Returns all the {WindowsError::ErrorCode} objects that match
    # the return value supplied.
    #
    # @param [Integer] retval the return value you want the error code for
    # @raise [ArgumentError] if something other than a Integer is supplied
    # @return [Array<WindowsError::ErrorCode>] all Win32 ErrorCodes that matched
    def self.find_by_retval(retval)
      raise ArgumentError, "Invalid Return Code!" unless retval.kind_of? Integer
      error_codes = []
      self.constants.each do |constant_name|
        error_code = self.const_get(constant_name)
        if error_code == retval
          error_codes << error_code
        end
      end
      error_codes
    end

    #
    # CONSTANTS
    #

    # (0x00000000) The client request is successful.
    STATUS_SUCCESS = WindowsError::ErrorCode.new('STATUS_SUCCESS', 0x00000000, 'The client request is successful.')

    # (0x00010002) An invalid SMB client request is received by the server.
    STATUS_INVALID_SMB = WindowsError::ErrorCode.new('STATUS_INVALID_SMB', 0x00010002, 'An invalid SMB client request is received by the server.')

    # (0x00050002) The client request received by the server contains an invalid TID value.
    STATUS_SMB_BAD_TID = WindowsError::ErrorCode.new('STATUS_SMB_BAD_TID', 0x00050002, 'The client request received by the server contains an invalid TID value.')

    # (0x00160002) The client request received by the server contains an unknown SMB command code.
    STATUS_SMB_BAD_COMMAND = WindowsError::ErrorCode.new('STATUS_SMB_BAD_COMMAND', 0x00160002, 'The client request received by the server contains an unknown SMB command code.')

    # (0x005B0002) The client request to the server contains an invalid UID value.
    STATUS_SMB_BAD_UID = WindowsError::ErrorCode.new('STATUS_SMB_BAD_UID', 0x005B0002, 'The client request to the server contains an invalid UID value.')

    # (0x00FB0002) The client request received by the server is for a non-standard SMB operation (for example, an SMB_COM_READ_MPX request on a non-disk share). The client SHOULD send another request with a different SMB command to perform this operation.
    STATUS_SMB_USE_STANDARD = WindowsError::ErrorCode.new('STATUS_SMB_USE_STANDARD', 0x00FB0002, 'The client request received by the server is for a non-standard SMB operation (for example, an SMB_COM_READ_MPX request on a non-disk share). The client SHOULD send another request with a different SMB command to perform this operation.')

    # (0x80000005) The data was too large to fit into the specified buffer.
    STATUS_BUFFER_OVERFLOW = WindowsError::ErrorCode.new('STATUS_BUFFER_OVERFLOW', 0x80000005, 'The data was too large to fit into the specified buffer.')

    # (0x80000006) No more files were found that match the file specification.
    STATUS_NO_MORE_FILES = WindowsError::ErrorCode.new('STATUS_NO_MORE_FILES', 0x80000006, 'No more files were found that match the file specification.')

    # (0x8000002D) The create operation stopped after reaching a symbolic link.
    STATUS_STOPPED_ON_SYMLINK = WindowsError::ErrorCode.new('STATUS_STOPPED_ON_SYMLINK', 0x8000002D, 'The create operation stopped after reaching a symbolic link.')

    # (0xC0000002) The requested operation is not implemented.
    STATUS_NOT_IMPLEMENTED = WindowsError::ErrorCode.new('STATUS_NOT_IMPLEMENTED', 0xC0000002, 'The requested operation is not implemented.')

    # (0xC000000D) The parameter specified in the request is not valid.
    STATUS_INVALID_PARAMETER = WindowsError::ErrorCode.new('STATUS_INVALID_PARAMETER', 0xC000000D, 'The parameter specified in the request is not valid.')

    # (0xC000000E) A device that does not exist was specified.
    STATUS_NO_SUCH_DEVICE = WindowsError::ErrorCode.new('STATUS_NO_SUCH_DEVICE', 0xC000000E, 'A device that does not exist was specified.')

    # (0xC0000010) The specified request is not a valid operation for the target device.
    STATUS_INVALID_DEVICE_REQUEST = WindowsError::ErrorCode.new('STATUS_INVALID_DEVICE_REQUEST', 0xC0000010, 'The specified request is not a valid operation for the target device.')

    # (0xC0000016) If extended security has been negotiated, then this error code can be returned in the SMB_COM_SESSION_SETUP_ANDX response from the server to indicate that additional authentication information is to be exchanged. See section 2.2.4.6 for details.
    STATUS_MORE_PROCESSING_REQUIRED = WindowsError::ErrorCode.new('STATUS_MORE_PROCESSING_REQUIRED', 0xC0000016, 'If extended security has been negotiated, then this error code can be returned in the SMB_COM_SESSION_SETUP_ANDX response from the server to indicate that additional authentication information is to be exchanged. See section 2.2.4.6 for details.')

    # (0xC0000022) The client did not have the required permission needed for the operation.
    STATUS_ACCESS_DENIED = WindowsError::ErrorCode.new('STATUS_ACCESS_DENIED', 0xC0000022, 'The client did not have the required permission needed for the operation.')

    # (0xC0000023) The buffer is too small to contain the entry. No information has been written to the buffer.
    STATUS_BUFFER_TOO_SMALL = WindowsError::ErrorCode.new('STATUS_BUFFER_TOO_SMALL', 0xC0000023, 'The buffer is too small to contain the entry. No information has been written to the buffer.')

    # (0xC0000034) The object name is not found.
    STATUS_OBJECT_NAME_NOT_FOUND = WindowsError::ErrorCode.new('STATUS_OBJECT_NAME_NOT_FOUND', 0xC0000034, 'The object name is not found.')

    # (0xC0000035) The object name already exists.
    STATUS_OBJECT_NAME_COLLISION = WindowsError::ErrorCode.new('STATUS_OBJECT_NAME_COLLISION', 0xC0000035, 'The object name already exists.')

    # (0xC000003A) The path to the directory specified was not found. This error is also returned on a create request if the operation requires the creation of more than one new directory level for the path specified.
    STATUS_OBJECT_PATH_NOT_FOUND = WindowsError::ErrorCode.new('STATUS_OBJECT_PATH_NOT_FOUND', 0xC000003A, 'The path to the directory specified was not found. This error is also returned on a create request if the operation requires the creation of more than one new directory level for the path specified.')

    # (0xC00000A5) A specified impersonation level is invalid. This error is also used to indicate that a required impersonation level was not provided.
    STATUS_BAD_IMPERSONATION_LEVEL = WindowsError::ErrorCode.new('STATUS_BAD_IMPERSONATION_LEVEL', 0xC00000A5, 'A specified impersonation level is invalid. This error is also used to indicate that a required impersonation level was not provided.')

    # (0xC00000B5) The specified I/O operation was not completed before the time-out period expired.
    STATUS_IO_TIMEOUT = WindowsError::ErrorCode.new('STATUS_IO_TIMEOUT', 0xC00000B5, 'The specified I/O operation was not completed before the time-out period expired.')

    # (0xC00000BA) The file that was specified as a target is a directory and the caller specified that it could be anything but a directory.
    STATUS_FILE_IS_A_DIRECTORY = WindowsError::ErrorCode.new('STATUS_FILE_IS_A_DIRECTORY', 0xC00000BA, 'The file that was specified as a target is a directory and the caller specified that it could be anything but a directory.')

    # (0xC00000BB) The client request is not supported.
    STATUS_NOT_SUPPORTED = WindowsError::ErrorCode.new('STATUS_NOT_SUPPORTED', 0xC00000BB, 'The client request is not supported.')

    # (0xC00000C9) The network name specified by the client has been deleted on the server. This error is returned if the client specifies an incorrect TID or the share on the server represented by the TID was deleted.
    STATUS_NETWORK_NAME_DELETED = WindowsError::ErrorCode.new('STATUS_NETWORK_NAME_DELETED', 0xC00000C9, 'The network name specified by the client has been deleted on the server. This error is returned if the client specifies an incorrect TID or the share on the server represented by the TID was deleted.')

    # (0xC0000203) The user session specified by the client has been deleted on the server. This error is returned by the server if the client sends an incorrect UID.
    STATUS_USER_SESSION_DELETED = WindowsError::ErrorCode.new('STATUS_USER_SESSION_DELETED', 0xC0000203, 'The user session specified by the client has been deleted on the server. This error is returned by the server if the client sends an incorrect UID.')

    # (0xC000035C) The client's session has expired; therefore, the client MUST re-authenticate to continue accessing remote resources.
    STATUS_NETWORK_SESSION_EXPIRED = WindowsError::ErrorCode.new('STATUS_NETWORK_SESSION_EXPIRED', 0xC000035C, 'The client\'s session has expired; therefore, the client MUST re-authenticate to continue accessing remote resources.')

    # (0xC000205A) The client has requested too many UID values from the server or the client already has an SMB session setup with this UID value.
    STATUS_SMB_TOO_MANY_UIDS = WindowsError::ErrorCode.new('STATUS_SMB_TOO_MANY_UIDS', 0xC000205A, 'The client has requested too many UID values from the server or the client already has an SMB session setup with this UID value.')
  end
end
