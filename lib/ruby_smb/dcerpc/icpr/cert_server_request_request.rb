require 'ruby_smb/dcerpc/ndr'

module RubySMB
  module Dcerpc
    module Icpr

      # [3.2.4.1.1 CertServerRequest (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7)
      class CertServerRequestRequest < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32           :dw_flags
        ndr_wide_stringz_ptr :pwsz_authority
        ndr_uint32           :pdw_request_id
        cert_trans_blob      :pctb_attribs
        cert_trans_blob      :pctb_request

        def initialize_instance
          super
          @opnum = CERT_SERVER_REQUEST
        end
      end

    end
  end
end
