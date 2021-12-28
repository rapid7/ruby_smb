module RubySMB
  module Dcerpc
    module Drsr

      # [4.1.4.1.4 DS_NAME_RESULT_ITEMW](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/e174fead-5a37-4a11-a0f6-69086e8dd4e9)
      class DsNameResultItemw < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32           :status
        ndr_wide_stringz_ptr :p_domain
        ndr_wide_stringz_ptr :p_name
      end

      class DsNameResultItemwArrayPtr < Ndr::NdrConfArray
        default_parameters type: :ds_name_result_itemw
        extend Ndr::PointerClassPlugin
      end

      # [4.1.4.1.5 DS_NAME_RESULTW](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/0076d241-3f79-4b0b-8e07-8ccfaff8bd4c)
      class DsNameResultw < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32                     :c_items
        ds_name_result_itemw_array_ptr :r_items
      end

      class DsNameResultwPtr < DsNameResultw
        default_parameters referent_byte_align: 4
        extend Ndr::PointerClassPlugin
      end

      #[4.1.4.1.7 DRS_MSG_CRACKREPLY_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/3419de89-0d54-462e-98ac-fb77292c91e7)
      class DrsMsgCrackreplyV1 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ds_name_resultw_ptr :p_result
      end

      # [4.1.4.1.6 DRS_MSG_CRACKREPLY](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/1dc605fe-dd85-481d-84a4-f4c5da812d57)
      class DrsMsgCrackreply < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32 :switch_type
        choice     :msg_crack, selection: :switch_type, byte_align: 4 do
          drs_msg_crackreply_v1 1
        end
      end

      # [4.1.4 IDL_DRSCrackNames (Opnum 12)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/9b4bfb44-6656-4404-bcc8-dc88111658b3)
      class DrsCrackNamesResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32         :dw_out_version
        drs_msg_crackreply :pmsg_out
        ndr_uint32         :error_status

        def initialize_instance
          super
          @opnum = DRS_CRACK_NAMES
        end
      end

    end
  end
end





