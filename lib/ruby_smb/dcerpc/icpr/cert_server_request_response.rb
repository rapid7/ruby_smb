require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Icpr

      # [3.2.4.1.1 CertServerRequest (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7)
      class CertServerRequestResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32      :pdw_request_id
        ndr_uint32      :pdw_disposition
        cert_trans_blob :pctb_cert
        cert_trans_blob :pctb_encoded_cert
        cert_trans_blob :pctb_disposition_message
        ndr_uint32      :error_status

        def initialize_instance
          super
          @opnum = CERT_SERVER_REQUEST
        end
      end

    end
  end
end
