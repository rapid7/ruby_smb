module RubySMB
  module Dcerpc
    module Lsarpc

      # This class represents a LsarQueryInformationPolicy2 Response Packet as defined in
      # [3.1.4.4.4 LsarQueryInformationPolicy2 (Opnum 46)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/516f503c-0230-489d-b012-e650b46b66a2)
      class LsarQueryInformationPolicy2Response < BinData::Record
        attr_reader :opnum

        endian :little

        lsapr_policy_information_ptr :policy_information
        ndr_uint32                   :error_status

        def initialize_instance
          super
          @opnum = LSAR_QUERY_INFORMATION_POLICY2
        end
      end

    end
  end
end
