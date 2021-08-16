require 'ruby_smb/error'

module RubySMB
  # Contains all the DCERPC specific Error classes.
  module Dcerpc
    module Error
      # Base class for DCERPC errors
      class DcerpcError < RubySMB::Error::RubySMBError; end

      # Raised when The Bind operation fails
      class BindError < DcerpcError; end

      # Raised when an invalid packet is received
      class InvalidPacket < DcerpcError; end

      # Raised when an error is returned during a Winreg operation
      class WinregError < DcerpcError; end

      # Raised when an error is returned during a Svcctl operation
      class SvcctlError < DcerpcError; end

      # Raised when an error is returned during a Samr operation
      class SamrError < DcerpcError; end

      # Raised when an error is returned during a Wkssvc operation
      class WkssvcError < DcerpcError; end

      # Raised when an error is returned during a Drsr operation
      class DrsrError < DcerpcError; end

      # Raised when an error occurs with the underlying socket.
      class CommunicationError < DcerpcError; end
    end
  end
end
