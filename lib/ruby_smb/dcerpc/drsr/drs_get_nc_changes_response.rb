module RubySMB
  module Dcerpc
    module Drsr

      #[4.1.10.2.10 DRS_MSG_GETCHGREPLY_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/bd70a9c3-c1d3-48cf-9c24-503a5567d09c)
      class DrsMsgGetchgreplyV1 < Ndr::NdrStruct
        include AttrtypResponsePlugin
        default_parameter byte_align: 8

        uuid                       :uuid_dsa_obj_src
        uuid                       :uuid_invoc_id_src
        ds_name_ptr                :p_nc
        usn_vector                 :usnvec_from
        usn_vector                 :usnvec_to
        uptodate_vector_v1_ext_ptr :p_up_to_date_vec_src_v1
        schema_prefix_table        :prefix_table_src
        ndr_uint32                 :ul_extended_ret
        ndr_uint32                 :c_num_objects
        ndr_uint32                 :c_num_bytes
        replentinflist_ptr         :p_objects
        ndr_boolean                :f_more_data
      end

      # [4.1.10.2.11 DRS_MSG_GETCHGREPLY_V2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/677d8fab-6aa1-4327-9b6f-62a6ad7fcfa3)
      class DrsMsgGetchgreplyV2 < Ndr::NdrStruct
        default_parameter byte_align: 4

        drs_compressed_blob :compressed_v1
      end

      # [4.1.10.2.12 DRS_MSG_GETCHGREPLY_V6](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/1317a654-5dd6-45ff-af73-919cbc7fbb45)
      class DrsMsgGetchgreplyV6 < Ndr::NdrStruct
        include AttrtypResponsePlugin
        default_parameter byte_align: 8

        uuid                       :uuid_dsa_obj_src
        uuid                       :uuid_invoc_id_src
        ds_name_ptr                :p_nc
        usn_vector                 :usnvec_from
        usn_vector                 :usnvec_to
        uptodate_vector_v2_ext_ptr :p_up_to_date_vec_src
        schema_prefix_table        :prefix_table_src
        ndr_uint32                 :ul_extended_ret
        ndr_uint32                 :c_num_objects
        ndr_uint32                 :c_num_bytes
        replentinflist_ptr         :p_objects
        ndr_boolean                :f_more_data
        ndr_uint32                 :c_num_nc_size_objects
        ndr_uint32                 :c_num_nc_size_values
        ndr_uint32                 :c_num_values
        replvalinf_v1_array_ptr    :rg_values
        ndr_uint32                 :dw_drs_error
      end

      # [4.1.10.2.13 DRS_MSG_GETCHGREPLY_V7](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/26eaca61-0f19-47e7-b304-2580e9870aa8)
      class DrsMsgGetchgreplyV7 < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32          :dw_compressed_version
        drs_comp_alg_type   :compression_alg
        drs_compressed_blob :compressed_any
      end

      # [4.1.10.2.14 DRS_MSG_GETCHGREPLY_V9](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b9564a19-4500-444b-a99b-0da1b08cdb6f)
      class DrsMsgGetchgreplyV9 < Ndr::NdrStruct
        include AttrtypResponsePlugin
        default_parameter byte_align: 8

        uuid                       :uuid_dsa_obj_src
        uuid                       :uuid_invoc_id_src
        ds_name_ptr                :p_nc
        usn_vector                 :usnvec_from
        usn_vector                 :usnvec_to
        uptodate_vector_v2_ext_ptr :p_up_to_date_vec_src
        schema_prefix_table        :prefix_table_src
        ndr_uint32                 :ul_extended_ret
        ndr_uint32                 :c_num_objects
        ndr_uint32                 :c_num_bytes
        replentinflist_ptr         :p_objects
        ndr_boolean                :f_more_data
        ndr_uint32                 :c_num_nc_size_objects
        ndr_uint32                 :c_num_nc_size_values
        ndr_uint32                 :c_num_values
        replvalinf_v3_array_ptr    :rg_values
        ndr_uint32                 :dw_drs_error
      end

      # [4.1.10.2.9 DRS_MSG_GETCHGREPLY](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/65a5cb42-c25f-4378-b06e-f87341b21f93)
      class DrsMsgGetchgreply < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32 :switch_type, initial_value: -> { @obj.parent.parent.pdw_out_version.to_i }
        choice     :msg_getchg, selection: :switch_type, byte_align: 4 do
          drs_msg_getchgreply_v1 1
          drs_msg_getchgreply_v2 2
          drs_msg_getchgreply_v6 6
          drs_msg_getchgreply_v7 7
          drs_msg_getchgreply_v9 9
        end
      end

      # [4.1.10 IDL_DRSGetNCChanges (Opnum 3)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894)
      class DrsGetNcChangesResponse < BinData::Record
        attr_reader :opnum

        ndr_uint32          :pdw_out_version
        drs_msg_getchgreply :pmsg_out
        ndr_uint32          :error_status

        def initialize_instance
          super
          @opnum = DRS_GET_NC_CHANGES
        end
      end

    end
  end
end
