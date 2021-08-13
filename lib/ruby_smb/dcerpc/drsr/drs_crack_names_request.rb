module RubySMB
  module Dcerpc
    module Drsr

      class DrsNameArrayPtr < Ndr::NdrConfArray
        default_parameters type: :ndr_wide_stringz_ptr
        extend Ndr::PointerClassPlugin
      end

      #[4.1.4.1.2 DRS_MSG_CRACKREQ_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b47debc0-59ee-40e4-ad0f-4bc9f96043b2)
      class DrsMsgCrackreqV1 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32         :code_page
        ndr_uint32         :locale_id
        ndr_uint32         :dw_flags
        ndr_uint32         :format_offered
        ndr_uint32         :format_desired
        ndr_uint32         :c_names, initial_value: -> { rp_names.size }
        drs_name_array_ptr :rp_names
      end

      # [4.1.4.1.1 DRS_MSG_CRACKREQ](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f2d5166e-09f6-4788-a391-66471b2f7d6d)
      class DrsMsgCrackreq < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32 :switch_type, initial_value: 1
        choice :msg_crack, selection: :switch_type, byte_align: 4 do
          drs_msg_crackreq_v1 1
        end
      end

      # [4.1.4 IDL_DRSCrackNames (Opnum 12)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/9b4bfb44-6656-4404-bcc8-dc88111658b3)
      class DrsCrackNamesRequest < BinData::Record
        attr_reader :opnum

        endian :little

        drs_handle       :h_drs
        ndr_uint32       :dw_in_version, initial_value: 1
        drs_msg_crackreq :pmsg_in

        def initialize_instance
          super
          @opnum = DRS_CRACK_NAMES
        end
      end

    end
  end
end




