module RubySMB
  module Dcerpc
    module Lsarpc

      # This class represents a LsarQueryInformationPolicy Response Packet as defined in
      # [3.1.4.4.4 LsarQueryInformationPolicy (Opnum 7)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/3564ba70-84ea-4f04-a9dc-dede9f96a8bf)
      class LsarQueryInformationPolicyResponse < BinData::Record
        attr_reader :opnum

        endian :little

        lsapr_policy_information_ptr :policy_information
        ndr_uint32                   :error_status

        def initialize_instance
          super
          @opnum = LSAR_QUERY_INFORMATION_POLICY
        end
      end

    end
  end
end
