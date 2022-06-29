module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.4.4 SamrCreateUser2InDomain (Opnum 50)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/a98d7fbb-1735-4fbf-b41a-ef363c899002)
      class SamrCreateUser2InDomainRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle         :domain_handle
        rpc_unicode_string   :name
        ndr_uint32           :account_type
        ndr_uint32           :desired_access

        def initialize_instance
          super
          @opnum = SAMR_CREATE_USER2_IN_DOMAIN
        end
      end

    end
  end
end
