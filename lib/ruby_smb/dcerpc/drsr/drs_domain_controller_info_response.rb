module RubySMB
  module Dcerpc
    module Drsr

      # [4.1.5.1.8 DS_DOMAIN_CONTROLLER_INFO_1W](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b30c5951-ccb1-4fb6-ba9a-5699d5d78759)
      class DsDomainControllerInfo1w < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_wide_stringz_ptr :netbios_name
        ndr_wide_stringz_ptr :dns_host_name
        ndr_wide_stringz_ptr :site_name
        ndr_wide_stringz_ptr :computer_object_name
        ndr_wide_stringz_ptr :server_object_name
        ndr_boolean          :f_is_pdc
        ndr_boolean          :f_ds_enabled
      end

      class DsDomainControllerInfo1wPtr < Ndr::NdrConfVarArray
        default_parameters type: :ds_domain_controller_info1w
        extend Ndr::PointerClassPlugin
      end

      #[4.1.5.1.4 DRS_MSG_DCINFOREPLY_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f71a8f6c-5426-4628-aa91-aeabef2c086f)
      class DrsMsgDcinforeplyV1 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32                      :c_items
        ds_domain_controller_info1w_ptr :r_items
      end

      # [4.1.5.1.9 DS_DOMAIN_CONTROLLER_INFO_2W](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/a9c9fd50-24b5-4ff7-b336-8e23ac0622de)
      class DsDomainControllerInfo2w < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_wide_stringz_ptr :netbios_name
        ndr_wide_stringz_ptr :dns_host_name
        ndr_wide_stringz_ptr :site_name
        ndr_wide_stringz_ptr :site_object_name
        ndr_wide_stringz_ptr :computer_object_name
        ndr_wide_stringz_ptr :server_object_name
        ndr_wide_stringz_ptr :ntds_dsa_object_name
        ndr_boolean          :f_is_pdc
        ndr_boolean          :f_ds_enabled
        ndr_boolean          :f_is_gc
        uuid                 :site_object_guid
        uuid                 :computer_object_guid
        uuid                 :server_object_guid
        uuid                 :ntds_dsa_object_guid
      end

      class DsDomainControllerInfo2wPtr < Ndr::NdrConfArray
        default_parameters type: :ds_domain_controller_info2w
        extend Ndr::PointerClassPlugin
      end

      #[4.1.5.1.5 DRS_MSG_DCINFOREPLY_V2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f567e605-01fe-4228-960e-14647c29f668)
      class DrsMsgDcinforeplyV2 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32                      :c_items
        ds_domain_controller_info2w_ptr :r_items
      end

      # [4.1.5.1.10 DS_DOMAIN_CONTROLLER_INFO_3W](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/08f99ee7-8235-482b-bfe5-c6170f133cd4)
      class DsDomainControllerInfo3w < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_wide_stringz_ptr :netbios_name
        ndr_wide_stringz_ptr :dns_host_name
        ndr_wide_stringz_ptr :site_name
        ndr_wide_stringz_ptr :site_object_name
        ndr_wide_stringz_ptr :computer_object_name
        ndr_wide_stringz_ptr :server_object_name
        ndr_wide_stringz_ptr :ntds_dsa_object_name
        ndr_boolean          :f_is_pdc
        ndr_boolean          :f_ds_enabled
        ndr_boolean          :f_is_gc
        ndr_boolean          :f_is_rodc
        uuid                 :site_object_guid
        uuid                 :computer_object_guid
        uuid                 :server_object_guid
        uuid                 :ntds_dsa_object_guid
      end

      class DsDomainControllerInfo3wPtr < Ndr::NdrConfVarArray
        default_parameters type: :ds_domain_controller_info3w
        extend Ndr::PointerClassPlugin
      end

      #[4.1.5.1.6 DRS_MSG_DCINFOREPLY_V3](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/cafc7232-c6da-4784-84d7-e5d8c804c2d9)
      class DrsMsgDcinforeplyV3 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32                      :c_items
        ds_domain_controller_info3w_ptr :r_items
      end

      # [4.1.5.1.11 DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/38259d46-11e6-4e74-8e0c-0b0f9ce2dab4)
      class DsDomainControllerInfoFfffffffw < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32           :ip_address
        ndr_uint32           :notification_count
        ndr_uint32           :sec_time_connected
        ndr_uint32           :flags
        ndr_uint32           :total_requests
        ndr_uint32           :reserved1
        ndr_wide_stringz_ptr :user_name
      end

      class DsDomainControllerInfoFfffffffwPtr < Ndr::NdrConfVarArray
        default_parameters type: :ds_domain_controller_info_ffffffffw
        extend Ndr::PointerClassPlugin
      end

      #[4.1.5.1.7 DRS_MSG_DCINFOREPLY_VFFFFFFFF](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/625c5133-cb5b-440a-9f53-232ae1b2dc3f)
      class DrsMsgDcinforeplyVffffffff < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32                              :c_items
        ds_domain_controller_info_ffffffffw_ptr :r_items
      end

      # [4.1.5.1.3 DRS_MSG_DCINFOREPLY](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/034282e5-7828-4353-ad6e-2688c65ab9fb)
      class DrsMsgDcinforeply < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32 :switch_type
        choice     :msg_dcinfo, selection: :switch_type, byte_align: 4 do
          drs_msg_dcinforeply_v1        1
          drs_msg_dcinforeply_v2        2
          drs_msg_dcinforeply_v3        3
          drs_msg_dcinforeply_vffffffff 0xFFFFFFFF
        end
      end

      # [4.1.5 IDL_DRSDomainControllerInfo (Opnum 16)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/668abdc8-1db7-4104-9dea-feab05ff1736)
      class DrsDomainControllerInfoResponse < BinData::Record
        attr_reader :opnum

        endian :little

        ndr_uint32          :dw_out_version
        drs_msg_dcinforeply :pmsg_out
        ndr_uint32          :error_status

        def initialize_instance
          super
          @opnum = DRS_DOMAIN_CONTROLLER_INFO
        end
      end

    end
  end
end




