module RubySMB
  module Dcerpc
    module Svcctl

      # [3.1.4.16 ROpenServiceW (Opnum 16)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6d0a4225-451b-4132-894d-7cef7aecfd2d)
      class OpenServiceWRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sc_rpc_handle :lp_sc_handle
        ndr_string    :lp_service_name
        string        :pad, length: -> { pad_length(self.lp_service_name) }
        uint32        :dw_desired_access

        def initialize_instance
          super
          @opnum = OPEN_SERVICE_W
        end

        # Determines the correct length for the padding, so that the next
        # field is 4-byte aligned.
        def pad_length(prev_element)
          offset = (prev_element.abs_offset + prev_element.to_binary_s.length) % 4
          (4 - offset) % 4
        end
      end

    end
  end
end
