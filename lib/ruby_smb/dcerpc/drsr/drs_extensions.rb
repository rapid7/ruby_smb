module RubySMB
  module Dcerpc
    module Drsr

      # [5.39 DRS_EXTENSIONS_INT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/3ee529b1-23db-4996-948a-042f04998e91)
      class DrsExtensionsInt < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32 :cb, initial_value: -> { num_bytes - 4 }
        ndr_uint32 :dw_flags
        uuid       :site_obj_guid
        int32      :pid, byte_align: 4
        ndr_uint32 :dw_repl_epoch
        ndr_uint32 :dw_flags_ext
        uuid       :config_obj_guid
        ndr_uint32 :dw_ext_caps
      end

      # [5.38 DRS_EXTENSIONS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/ed0c5dc1-7566-48b3-be08-4c5e26ba60c4)
      class DrsExtensions < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32     :cb, initial_value: -> { self.rgb.size }
        ndr_conf_array :rgb, type: :ndr_uint8

        def assign(val)
          case val
          when String
            self.rgb.assign(val.bytes)
          when Array
            self.rgb.assign(val.to_ary)
          when DrsExtensionsInt
            self.rgb.assign(val.to_binary_s[4..-1].bytes)
          when Hash
            if (field_names & val.keys).empty?
              # Cannot assign this hash to the structrue, it is likely
              # DrsExtensionsInt hash values we need to transform in byte array.
              drs_ext = DrsExtensionsInt.new(val).to_binary_s
              self.rgb.assign(drs_ext[4..-1].bytes)
            end
          else
            super
          end
        end
      end

      class DrsExtensionsPtr < DrsExtensions
        extend Ndr::PointerClassPlugin
      end

    end
  end
end

