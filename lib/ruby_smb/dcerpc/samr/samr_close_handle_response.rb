module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.13.1 SamrCloseHandle (Opnum 1)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/55d134df-e257-48ad-8afa-cb2ca45cd3cc)
      class SamrCloseHandleResponse < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle :sam_handle
        ndr_uint32   :error_status

        def initialize_instance
          super
          @opnum = SAMR_CLOSE_HANDLE
        end
      end

    end
  end
end


