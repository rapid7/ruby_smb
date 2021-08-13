require 'openssl'

module RubySMB
  module Dcerpc
    module Drsr

      #[4.1.10.2.2 DRS_MSG_GETCHGREQ_V3](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/6a2a056c-ac7f-47d0-9e6d-9023a4e5947c)
      class DrsMsgGetchgreqV3 < Ndr::NdrStruct
        include AttrtypRequestPlugin
        default_parameter byte_align: 8

        uuid                           :uuid_dsa_obj_dest
        uuid                           :uuid_invoc_id_src
        ds_name_ptr                    :p_nc
        usn_vector                     :usnvec_from
        uptodate_vector_v1_ext_ptr     :p_up_to_date_vec_dest_v1
        partial_attr_vector_v1_ext_ptr :p_partial_attr_vec_dest_v1
        schema_prefix_table            :prefix_table_dest
        ndr_uint32                     :ul_flags
        ndr_uint32                     :c_max_objects
        ndr_uint32                     :c_max_bytes
        ndr_uint32                     :ul_extended_op
      end

      # [4.1.10.2.3 DRS_MSG_GETCHGREQ_V4](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/9db4db21-8ccd-4c81-8662-6e2baff8426c)
      class DrsMsgGetchgreqV4 < Ndr::NdrStruct
        default_parameter byte_align: 8

        uuid                 :uuid_transport_obj
        mtx_addr_ptr         :pmtx_return_address
        drs_msg_getchgreq_v3 :v3
      end

      #[4.1.10.2.4 DRS_MSG_GETCHGREQ_V5](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/fd24b73c-7b81-43af-8c77-65bc2e3181b7)
      class DrsMsgGetchgreqV5 < Ndr::NdrStruct
        default_parameter byte_align: 8

        uuid                       :uuid_dsa_obj_dest
        uuid                       :uuid_invoc_id_src
        ds_name_ptr                :p_nc
        usn_vector                 :usnvec_from
        uptodate_vector_v1_ext_ptr :p_up_to_date_vec_dest_v1
        ndr_uint32                 :ul_flags
        ndr_uint32                 :c_max_objects
        ndr_uint32                 :c_max_bytes
        ndr_uint32                 :ul_extended_op
        ndr_uint64                 :li_fsmo_info
      end

      #[4.1.10.2.5 DRS_MSG_GETCHGREQ_V7](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/5ef4f597-a397-4f6f-a98b-7a034247d886)
      class DrsMsgGetchgreqV7 < DrsMsgGetchgreqV4
        include AttrtypRequestPlugin
        default_parameter byte_align: 8

        partial_attr_vector_v1_ext_ptr :p_partial_attr_set
        partial_attr_vector_v1_ext_ptr :p_partial_attr_set_ex
        schema_prefix_table            :prefix_table_dest
      end

      #[4.1.10.2.6 DRS_MSG_GETCHGREQ_V8](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/4304bb4a-e9b5-4c8a-8731-df4d6f9ab567)
      class DrsMsgGetchgreqV8 < DrsMsgGetchgreqV5
        include AttrtypRequestPlugin
        default_parameter byte_align: 8

        partial_attr_vector_v1_ext_ptr :p_partial_attr_set
        partial_attr_vector_v1_ext_ptr :p_partial_attr_set_ex
        schema_prefix_table            :prefix_table_dest
      end

      #[4.1.10.2.7 DRS_MSG_GETCHGREQ_V10](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/92b1b77d-2058-46e0-9e8c-6664b96a0cf9)
      class DrsMsgGetchgreqV10 < DrsMsgGetchgreqV8
        default_parameter byte_align: 8

        ndr_uint32                     :ul_more_flags
      end

      #[4.1.10.2.8 DRS_MSG_GETCHGREQ_V11](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/cb2bab15-950b-48f8-af00-118e186a1311)
      class DrsMsgGetchgreqV11 < DrsMsgGetchgreqV10
        default_parameter byte_align: 8

        uuid                             :correlation_id
        var_size_buffer_with_version_ptr :p_reserved_buffer
      end

      # [4.1.10.2.1 DRS_MSG_GETCHGREQ](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/6a2a056c-ac7f-47d0-9e6d-9023a4e5947c)
      class DrsMsgGetchgreq < Ndr::NdrStruct
        default_parameter byte_align: 8

        ndr_uint32 :switch_type, initial_value: -> { @obj.parent.parent.dw_in_version.to_i }
        choice     :msg_getchg, selection: :switch_type, byte_align: 8 do
          drs_msg_getchgreq_v4  4
          drs_msg_getchgreq_v5  5
          drs_msg_getchgreq_v7  7
          drs_msg_getchgreq_v8  8
          drs_msg_getchgreq_v10 10
          drs_msg_getchgreq_v11 11
        end
      end

      # [4.1.10 IDL_DRSGetNCChanges (Opnum 3)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894)
      class DrsGetNcChangesRequest < BinData::Record
        attr_reader :opnum

        drs_handle        :h_drs
        ndr_uint32        :dw_in_version
        drs_msg_getchgreq :pmsg_in

        def initialize_instance
          super
          @opnum = DRS_GET_NC_CHANGES
        end
      end

    end
  end
end





