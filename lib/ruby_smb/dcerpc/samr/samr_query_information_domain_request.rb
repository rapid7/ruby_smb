module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.5.2 SamrQueryInformationDomain (Opnum 8)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/5d6a2817-caa9-41ca-a269-fd13ecbb4fa8)
      class SamrQueryInformationDomainRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :domain_handle
        ndr_uint16   :domain_information_class

        def initialize_instance
          super
          @opnum = SAMR_QUERY_INFORMATION_DOMAIN
        end
      end

    end
  end
end
