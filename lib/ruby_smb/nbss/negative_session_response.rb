module RubySMB
  module Nbss


    # Representation of the NetBIOS Negative Session Service Response packet as defined in
    # [4.3.4 SESSION REQUEST PACKET](https://tools.ietf.org/html/rfc1002)
    class NegativeSessionResponse < BinData::Record
      # NBSS error codes (RFC 1002 section 4.3.6)
      NOT_LISTENING_ON_CALLED_NAME       = 0x80
      NOT_LISTENING_FOR_CALLING_NAME     = 0x81
      CALLED_NAME_NOT_PRESENT            = 0x82
      CALLED_NAME_INSUFFICIENT_RESOURCES = 0x83
      UNSPECIFIED_ERROR                  = 0x8F

      endian :big

      session_header :session_header
      uint8          :error_code, label: 'Error Code'

      def error_msg
        case error_code
        when NOT_LISTENING_ON_CALLED_NAME
          'Not listening on called name'
        when NOT_LISTENING_FOR_CALLING_NAME
          'Not listening for calling name'
        when CALLED_NAME_NOT_PRESENT
          'Called name not present'
        when CALLED_NAME_INSUFFICIENT_RESOURCES
          'Called name present, but insufficient resources'
        when UNSPECIFIED_ERROR
          'Unspecified error'
        end
      end
    end

  end
end
