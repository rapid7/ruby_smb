module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      # This class represents a BaseRegQueryInfoKey Request Packet as defined in
      # [3.1.5.16 BaseRegQueryInfoKey (Opnum 16)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/a886ba66-5c7b-4331-bacd-7c77edc95d85)
      class QueryInfoKeyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey           :hkey
        rrp_unicode_string :lp_class

        def initialize_instance
          super
          @opnum = REG_QUERY_INFO_KEY
        end
      end

    end
  end
end


