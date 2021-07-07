module RubySMB
  module Dcerpc
    module Samr

      #[2.4.1.1 RPC_SID_IDENTIFIER_AUTHORITY](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/d7e6e5a5-437c-41e5-8ba1-bdfd43e96cbc)
      class RpcSidIdentifierAuthority < Ndr::NdrFixArray
        default_parameters type: :ndr_uint8, initial_length: 6, byte_align: 1
      end

      # [2.4.2.3 RPC_SID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/5cb97814-a1c2-4215-b7dc-76d1f4bfad01)
      class RpcSid < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint8 :revision
        ndr_uint8 :sub_authority_count, initial_value: -> { self.sub_authority.size }
        rpc_sid_identifier_authority :identifier_authority
        ndr_conf_array :sub_authority, type: :ndr_uint32

        def snapshot
          sid = ['S', self.revision.to_s, self.identifier_authority[-1].to_s]
          self.sub_authority.each { |e| sid << e.to_s }
          sid.join('-')
        end

        def assign(val)
          case val
          when String
            elems = val.split('-')
            raise ArgumentError, "Wrong SID format" unless elems[0].downcase == 's'
            self.revision = elems[1].to_i
            self.sub_authority_count = elems[3..-1].size
            self.identifier_authority = [0, 0, 0, 0, 0, elems[2].to_i]
            self.sub_authority = elems[3..-1].map(&:to_i)
          when RpcSid
            super
          else
            raise ArgumentError, "Can only assign String or other RpcSid object (got #{val.class})"
          end
          self
        end
      end

      class PrpcSid < RpcSid
        extend Ndr::PointerClassPlugin
      end

    end
  end
end
