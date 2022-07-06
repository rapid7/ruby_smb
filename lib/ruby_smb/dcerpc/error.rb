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

      # Raised when a fault response is received
      class FaultError < InvalidPacket
        attr_reader :status_code
        def initialize(message=nil, status:)
          @status_code = status
          super(message)
        end

        def status_name
          RubySMB::Dcerpc::Fault::Status.name(@status_code)
        end
      end

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

      # Raised when an error is returned during a Epm operation
      class EpmError < DcerpcError; end

      # Raised when an error is returned during a Dfsnm operation
      class DfsnmError < DcerpcError
        include RubySMB::Error::UnexpectedStatusCode::Mixin

        def initialize(msg, status_code: nil)
          self.status_code = status_code unless status_code.nil?

          super(msg)
        end
      end
    end
  end
end
