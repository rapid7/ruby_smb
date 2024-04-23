module RubySMB
  module Dcerpc
    module Lsarpc

      # This class represents a LsarOpenPolicy2 Response Packet as defined in
      # [3.1.4.4.1 LsarOpenPolicy2 (Opnum 44)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/9456a963-7c21-4710-af77-d0a2f5a72d6b)
      class LsarOpenPolicy2Response < BinData::Record
        attr_reader :opnum

        endian :little

        lsapr_handle :policy_handle
        ndr_uint32   :error_status

        def initialize_instance
          super
          @opnum = LSAR_OPEN_POLICY2
        end
      end

    end
  end
end
