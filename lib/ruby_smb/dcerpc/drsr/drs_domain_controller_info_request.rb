module RubySMB
  module Dcerpc
    module Drsr

      #[4.1.5.1.2 DRS_MSG_DCINFOREQ_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/18b23122-a1c2-4367-a677-592e0d4eef18)
      class DrsMsgDcinforeqV1 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_wide_stringz_ptr :domain
        ndr_uint32           :info_level
      end

      # [4.1.5.1.1 DRS_MSG_DCINFOREQ](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/6ac9ec30-5bfb-4970-860c-3971eb815930)
      class DrsMsgDcinforeq < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32 :switch_type, initial_value: 1
        choice     :msg_dcinfo, selection: :switch_type, byte_align: 4 do
          drs_msg_dcinforeq_v1 1
        end
      end

      # [4.1.5 IDL_DRSDomainControllerInfo (Opnum 16)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/668abdc8-1db7-4104-9dea-feab05ff1736)
      class DrsDomainControllerInfoRequest < BinData::Record
        attr_reader :opnum

        endian :little

        drs_handle        :h_drs
        ndr_uint32        :dw_in_version, initial_value: 1
        drs_msg_dcinforeq :pmsg_in

        def initialize_instance
          super
          @opnum = DRS_DOMAIN_CONTROLLER_INFO
        end
      end

    end
  end
end



