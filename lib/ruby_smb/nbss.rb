module RubySMB
  # Namespace for all of the NetBIOS packets used by RubySMB
  module Nbss
    # Session Packet Types
    SESSION_MESSAGE           = 0x00
    SESSION_REQUEST           = 0x81
    POSITIVE_SESSION_RESPONSE = 0x82
    NEGATIVE_SESSION_RESPONSE = 0x83
    RETARGET_SESSION_RESPONSE = 0x84
    SESSION_KEEP_ALIVE        = 0x85

    # NBSS negative session response error codes (RFC 1002 section 4.3.6)
    NOT_LISTENING_ON_CALLED_NAME       = 0x80
    NOT_LISTENING_FOR_CALLING_NAME     = 0x81
    CALLED_NAME_NOT_PRESENT            = 0x82
    CALLED_NAME_INSUFFICIENT_RESOURCES = 0x83
    UNSPECIFIED_ERROR                  = 0x8F

    require 'ruby_smb/nbss/netbios_name'
    require 'ruby_smb/nbss/session_header'
    require 'ruby_smb/nbss/session_request'
    require 'ruby_smb/nbss/negative_session_response'
    require 'ruby_smb/nbss/name_service_opcode'
    require 'ruby_smb/nbss/name_service_header_flags'
    require 'ruby_smb/nbss/name_service_result_code'
    require 'ruby_smb/nbss/node_status_request'
    require 'ruby_smb/nbss/node_status_response'
    require 'ruby_smb/nbss/node_status'
  end
end
