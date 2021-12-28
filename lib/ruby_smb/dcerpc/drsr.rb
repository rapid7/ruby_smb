module RubySMB
  module Dcerpc
    module Drsr

      UUID = 'E3514235-4B06-11D1-AB04-00C04FC2DCD2'
      VER_MAJOR = 4
      VER_MINOR = 0

      # [5.138 NTSAPI_CLIENT_GUID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/d4ff2fb2-bf57-455e-9646-426a92737d6e)
      NTSAPI_CLIENT_GUID = 'e24d201a-4fd6-11d1-a3da-0000f875ae0d'

      # Operation numbers
      DRS_BIND                   = 0x0000
      DRS_UNBIND                 = 0x0001
      DRS_GET_NC_CHANGES         = 0x0003
      DRS_CRACK_NAMES            = 0x000C
      DRS_DOMAIN_CONTROLLER_INFO = 0x0010


      # DRS_EXTENSIONS_INT Flags
      # [5.39 DRS_EXTENSIONS_INT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/3ee529b1-23db-4996-948a-042f04998e91)
      DRS_EXT_BASE                               = 0x00000001
      DRS_EXT_ASYNCREPL                          = 0x00000002
      DRS_EXT_REMOVEAPI                          = 0x00000004
      DRS_EXT_MOVEREQ_V2                         = 0x00000008
      DRS_EXT_GETCHG_DEFLATE                     = 0x00000010
      DRS_EXT_DCINFO_V1                          = 0x00000020
      DRS_EXT_RESTORE_USN_OPTIMIZATION           = 0x00000040
      DRS_EXT_ADDENTRY                           = 0x00000080
      DRS_EXT_KCC_EXECUTE                        = 0x00000100
      DRS_EXT_ADDENTRY_V2                        = 0x00000200
      DRS_EXT_LINKED_VALUE_REPLICATION           = 0x00000400
      DRS_EXT_DCINFO_V2                          = 0x00000800
      DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD       = 0x00001000
      DRS_EXT_CRYPTO_BIND                        = 0x00002000
      DRS_EXT_GET_REPL_INFO                      = 0x00004000
      DRS_EXT_STRONG_ENCRYPTION                  = 0x00008000
      DRS_EXT_DCINFO_VFFFFFFFF                   = 0x00010000
      DRS_EXT_TRANSITIVE_MEMBERSHIP              = 0x00020000
      DRS_EXT_ADD_SID_HISTORY                    = 0x00040000
      DRS_EXT_POST_BETA3                         = 0x00080000
      DRS_EXT_GETCHGREQ_V5                       = 0x00100000
      DRS_EXT_GETMEMBERSHIPS2                    = 0x00200000
      DRS_EXT_GETCHGREQ_V6                       = 0x00400000
      DRS_EXT_NONDOMAIN_NCS                      = 0x00800000
      DRS_EXT_GETCHGREQ_V8                       = 0x01000000
      DRS_EXT_GETCHGREPLY_V5                     = 0x02000000
      DRS_EXT_GETCHGREPLY_V6                     = 0x04000000
      DRS_EXT_GETCHGREPLY_V9                     = 0x00000100
      DRS_EXT_WHISTLER_BETA3                     = 0x08000000
      DRS_EXT_W2K3_DEFLATE                       = 0x10000000
      DRS_EXT_GETCHGREQ_V10                      = 0x20000000
      DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2 = 0x40000000
      DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3 = 0x80000000

      # DRS_EXTENSIONS_INT FlagsExt
      # [5.39 DRS_EXTENSIONS_INT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/3ee529b1-23db-4996-948a-042f04998e91)
      DRS_EXT_ADAM                = 0x00000001
      DRS_EXT_LH_BETA2            = 0x00000002
      DRS_EXT_RECYCLE_BIN         = 0x00000004
      # DRS_EXT_GETCHGREPLY_V9      = 0x00000100 (already defined)
      DRS_EXT_RPC_CORRELATIONID_1 = 0x00000400


      # [5.41 DRS_OPTIONS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/ac9c8a11-cd46-4080-acbf-9faa86344030)
      DRS_ASYNC_OP                  = 0x00000001
      DRS_GETCHG_CHECK              = 0x00000002
      DRS_UPDATE_NOTIFICATION       = 0x00000002
      DRS_ADD_REF                   = 0x00000004
      DRS_SYNC_ALL                  = 0x00000008
      DRS_DEL_REF                   = 0x00000008
      DRS_WRIT_REP                  = 0x00000010
      DRS_INIT_SYNC                 = 0x00000020
      DRS_PER_SYNC                  = 0x00000040
      DRS_MAIL_REP                  = 0x00000080
      DRS_ASYNC_REP                 = 0x00000100
      DRS_IGNORE_ERROR              = 0x00000100
      DRS_TWOWAY_SYNC               = 0x00000200
      DRS_CRITICAL_ONLY             = 0x00000400
      DRS_GET_ANC                   = 0x00000800
      DRS_GET_NC_SIZE               = 0x00001000
      DRS_LOCAL_ONLY                = 0x00001000
      DRS_NONGC_RO_REP              = 0x00002000
      DRS_SYNC_BYNAME               = 0x00004000
      DRS_REF_OK                    = 0x00004000
      DRS_FULL_SYNC_NOW             = 0x00008000
      DRS_NO_SOURCE                 = 0x00008000
      DRS_FULL_SYNC_IN_PROGRESS     = 0x00010000
      DRS_FULL_SYNC_PACKET          = 0x00020000
      DRS_SYNC_REQUEUE              = 0x00040000
      DRS_SYNC_URGENT               = 0x00080000
      DRS_REF_GCSPN                 = 0x00100000
      DRS_NO_DISCARD                = 0x00100000
      DRS_NEVER_SYNCED              = 0x00200000
      DRS_SPECIAL_SECRET_PROCESSING = 0x00400000
      DRS_INIT_SYNC_NOW             = 0x00800000
      DRS_PREEMPTED                 = 0x01000000
      DRS_SYNC_FORCED               = 0x02000000
      DRS_DISABLE_AUTO_SYNC         = 0x04000000
      DRS_DISABLE_PERIODIC_SYNC     = 0x08000000
      DRS_USE_COMPRESSION           = 0x10000000
      DRS_NEVER_NOTIFY              = 0x20000000
      DRS_SYNC_PAS                  = 0x40000000
      DRS_GET_ALL_GROUP_MEMBERSHIP  = 0x80000000

      # [4.1.10.2.22 EXOP_REQ Codes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/05de65ee-af0d-46d1-a9c8-4f0f856031cb)
      EXOP_FSMO_REQ_ROLE = 0x00000001
      EXOP_FSMO_REQ_RID_ALLOC = 0x00000002
      EXOP_FSMO_RID_REQ_ROLE = 0x00000003
      EXOP_FSMO_REQ_PDC = 0x00000004
      EXOP_FSMO_ABANDON_ROLE = 0x00000005
      EXOP_REPL_OBJ = 0x00000006
      EXOP_REPL_SECRETS = 0x00000007

      # Enumeration for identifying a compression algorithm.
      # [4.1.10.2.18 DRS_COMP_ALG_TYPE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/bb303730-0667-49f0-b117-288404c4b4cb)
      DRS_COMP_ALG_NONE = 0,
      DRS_COMP_ALG_UNUSED = 1,
      DRS_COMP_ALG_MSZIP = 2,
      DRS_COMP_ALG_WIN2K3 = 3

      # [4.1.10.2.21 EXOP_ERR Codes](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/bb303730-0667-49f0-b117-288404c4b4cb)
      EXOP_ERR_SUCCESS               = 0x00000001
      EXOP_ERR_UNKNOWN_OP            = 0x00000002
      EXOP_ERR_FSMO_NOT_OWNER        = 0x00000003
      EXOP_ERR_UPDATE_ERR            = 0x00000004
      EXOP_ERR_EXCEPTION             = 0x00000005
      EXOP_ERR_UNKNOWN_CALLER        = 0x00000006
      EXOP_ERR_RID_ALLOC             = 0x00000007
      EXOP_ERR_FSMO_OWNER_DELETED    = 0x00000008
      EXOP_ERR_FSMO_PENDING_OP       = 0x00000009
      EXOP_ERR_MISMATCH              = 0x0000000A
      EXOP_ERR_COULDNT_CONTACT       = 0x0000000B
      EXOP_ERR_FSMO_REFUSING_ROLES   = 0x0000000C
      EXOP_ERR_DIR_ERROR             = 0x0000000D
      EXOP_ERR_FSMO_MISSING_SETTINGS = 0x0000000E
      EXOP_ERR_ACCESS_DENIED         = 0x0000000F
      EXOP_ERR_PARAM_ERROR           = 0x00000010

      # DRS_MSG_CRACKREQ_V1 dwFlags
      # [4.1.4.1.2 DRS_MSG_CRACKREQ_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b47debc0-59ee-40e4-ad0f-4bc9f96043b2)
      DS_NAME_FLAG_GCVERIFY             = 0x00000004
      DS_NAME_FLAG_TRUST_REFERRAL       = 0x00000008
      DS_NAME_FLAG_PRIVATE_RESOLVE_FPOS = 0x80000000

      # [4.1.4.1.3 DS_NAME_FORMAT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/73c73cf2-0824-4d65-97f4-f56244f3e8a6)
      DS_UNKNOWN_NAME            = 0x00000000,
      DS_FQDN_1779_NAME          = 0x00000001,
      DS_NT4_ACCOUNT_NAME        = 0x00000002,
      DS_DISPLAY_NAME            = 0x00000003,
      DS_UNIQUE_ID_NAME          = 0x00000006,
      DS_CANONICAL_NAME          = 0x00000007,
      DS_USER_PRINCIPAL_NAME     = 0x00000008,
      DS_CANONICAL_NAME_EX       = 0x00000009,
      DS_SERVICE_PRINCIPAL_NAME  = 0x0000000A,
      DS_SID_OR_SID_HISTORY_NAME = 0x0000000B,
      DS_DNS_DOMAIN_NAME         = 0x0000000C

      # formatOffered: DS_NAME_FORMAT flags, plus these flags
      DS_LIST_SITES                       = 0xFFFFFFFF
      DS_LIST_SERVERS_IN_SITE             = 0xFFFFFFFE
      DS_LIST_DOMAINS_IN_SITE             = 0xFFFFFFFD
      DS_LIST_SERVERS_FOR_DOMAIN_IN_SITE  = 0xFFFFFFFC
      DS_LIST_INFO_FOR_SERVER             = 0xFFFFFFFB
      DS_LIST_ROLES                       = 0xFFFFFFFA
      DS_NT4_ACCOUNT_NAME_SANS_DOMAIN     = 0xFFFFFFF9
      DS_MAP_SCHEMA_GUID                  = 0xFFFFFFF8
      DS_LIST_DOMAINS                     = 0xFFFFFFF7
      DS_LIST_NCS                         = 0xFFFFFFF6
      DS_ALT_SECURITY_IDENTITIES_NAME     = 0xFFFFFFF5
      DS_STRING_SID_NAME                  = 0xFFFFFFF4
      DS_LIST_SERVERS_WITH_DCS_IN_SITE    = 0xFFFFFFF3
      DS_LIST_GLOBAL_CATALOG_SERVERS      = 0xFFFFFFF1
      DS_NT4_ACCOUNT_NAME_SANS_DOMAIN_EX  = 0xFFFFFFF0
      DS_USER_PRINCIPAL_NAME_AND_ALTSECID = 0xFFFFFFEF

      # formatDesired: DS_NAME_FORMAT flags, plus these flags
      DS_USER_PRINCIPAL_NAME_FOR_LOGON = 0xFFFFFFF2
      # DS_STRING_SID_NAME             = 0xFFFFFFF4 (already defined)



      ATTRTYP_TO_ATTID = {
          'userPrincipalName'       => '1.2.840.113556.1.4.656',
          'sAMAccountName'          => '1.2.840.113556.1.4.221',
          'unicodePwd'              => '1.2.840.113556.1.4.90',
          'dBCSPwd'                 => '1.2.840.113556.1.4.55',
          'ntPwdHistory'            => '1.2.840.113556.1.4.94',
          'lmPwdHistory'            => '1.2.840.113556.1.4.160',
          'supplementalCredentials' => '1.2.840.113556.1.4.125',
          'objectSid'               => '1.2.840.113556.1.4.146',
          'pwdLastSet'              => '1.2.840.113556.1.4.96',
          'userAccountControl'      => '1.2.840.113556.1.4.8',
          'accountExpires'          => '1.2.840.113556.1.4.159',
          'lastLogonTimestamp'      => '1.2.840.113556.1.4.1696'
      }

      class DrsHandle < Ndr::NdrContextHandle; end

      class DrsConfStringz16 < Ndr::NdrConfArray
        extend Ndr::ArrayClassPlugin
        default_parameters type: :ndr_wide_char
      end

      # [5.50 DSNAME](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/385d478f-3eb6-4d2c-ac58-f25c4debdd86)
      class DsName < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        # We don't want to include ref_id (4 bytes) if it is a pointer
        ndr_uint32         :struct_len, initial_value: -> { @obj.parent.respond_to?(:ref_id) ? num_bytes - 4 : num_bytes }
        ndr_uint32         :sid_len
        uuid               :guid
        string             :sid, byte_align: 1, length: 28
        ndr_uint32         :name_len, initial_value: -> { string_name.max_count - 1 }
        drs_conf_stringz16 :string_name
      end

      class DsNamePtr < DsName
        default_parameters referent_byte_align: 4
        extend Ndr::PointerClassPlugin
      end

      # [5.209 USN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/1be1e991-a2db-4f91-9953-8eab69f60e64)
      class Usn < BinData::Int64le
        default_parameter byte_align: 8
      end

      # [5.210 USN_VECTOR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/595d11b8-6ca7-4a61-bd56-3e6a2b99b76b)
      class UsnVector < Ndr::NdrStruct
        default_parameter byte_align: 8

        usn :usn_high_obj_update
        usn :usn_reserved
        usn :usn_high_prop_update
      end

      # [5.202 UPTODATE_CURSOR_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/cf88f341-fb49-4cd5-b7e2-6920cbd91f1b)
      class UptodateCursorV1 < Ndr::NdrStruct
        default_parameter byte_align: 8

        uuid :uuid_dsa
        usn  :usn_high_prop_update
      end

      # [5.204 UPTODATE_VECTOR_V1_EXT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/462b424a-b50a-4c4a-a81f-48d0f4cf40fe)
      class UptodateVectorV1Ext < Ndr::NdrStruct
        default_parameter byte_align: 8

        ndr_uint32     :dw_version
        ndr_uint32     :dw_reserved1
        ndr_uint32     :c_num_cursors
        ndr_uint32     :dw_reserved2
        ndr_conf_array :rg_cursors, type: :uptodate_cursor_v1
      end

      class UptodateVectorV1ExtPtr < UptodateVectorV1Ext
        default_parameters referent_byte_align: 8
        extend Ndr::PointerClassPlugin
      end

      module AttrtypRequestPlugin
        # [5.16.4 ATTRTYP-to-OID Conversion](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/6f53317f-2263-48ee-86c1-4580bf97232c)
        def add_attrtyp_from_oid(oid, to_field: :p_partial_attr_set)
          last_value = oid.split('.').last.to_i
          binary_oid = OpenSSL::ASN1::ObjectId.new(oid).to_der[2..-1]
          if last_value < 128
            oid_prefix = binary_oid[0...-1].bytes
          else
            oid_prefix = binary_oid[0...-2].bytes
          end

          prefix_table = self.prefix_table_dest.p_prefix_entry
          prefix_table.instantiate_referent if prefix_table.is_null_ptr?
          pos = prefix_table.size
          index = prefix_table.to_ary.index { |e| e.prefix.elements == oid_prefix }
          if index
            pos = index
          else
            entry = PrefixTableEntry.new(ndx: pos)
            entry.prefix.elements = oid_prefix
            prefix_table << entry
          end

          lower_word = last_value % 0x4000
          # mark it so that it is known to not be the whole lastValue
          lower_word += 0x8000 if last_value >= 0x4000
          upper_word = pos
          attrtyp = (upper_word << 16) + lower_word
          attr_set_field = send(to_field)
          attr_set_field.instantiate_referent if attr_set_field.is_null_ptr?
          attr_set_field.rg_partial_attr << attrtyp
        end
      end

      module AttrtypResponsePlugin
        # [5.16.4 ATTRTYP-to-OID Conversion](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/6f53317f-2263-48ee-86c1-4580bf97232c)
        def oid_from_attid(attr_typ)
          upper_word = attr_typ / 0x10000
          lower_word = attr_typ % 0x10000
          prefix_table = self.prefix_table_src.p_prefix_entry
          binary_oid = nil
          prefix_table.each do |prefix_table_entry|
            if prefix_table_entry.ndx == upper_word
              binary_oid = prefix_table_entry.prefix.elements.to_ary.pack('C*')
              if lower_word < 128
                binary_oid << [lower_word].pack('C')
              else
                lower_word -= 0x8000 if lower_word >= 0x8000
                binary_oid << [((lower_word / 128) % 128) + 128].pack('C')
                binary_oid << [lower_word % 128].pack('C')
              end
              break
            end
          end

          return unless binary_oid
          OpenSSL::ASN1.decode("\x06#{[binary_oid.length].pack('C')}#{binary_oid}").value
        end
      end

      # [5.14 ATTRTYP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/91173129-08e6-497c-8266-b5ac0aa5f983)
      class Attrtyp < Ndr::NdrUint32; end

      # [5.146 PARTIAL_ATTR_VECTOR_V1_EXT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/1d5c1b34-daa4-4761-a8b5-d3c0146a0e30)
      class PartialAttrVectorV1Ext < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32     :dw_version, initial_value: 1
        ndr_uint32     :dw_reserved1
        ndr_uint32     :c_attrs, initial_value: -> { rg_partial_attr.max_count }
        ndr_conf_array :rg_partial_attr, type: :attrtyp
      end

      class PartialAttrVectorV1ExtPtr < PartialAttrVectorV1Ext
        default_parameters referent_byte_align: 4
        extend Ndr::PointerClassPlugin
      end

      class DrsByteArrayPtr < Ndr::NdrConfArray
        default_parameters type: :ndr_uint8
        extend Ndr::PointerClassPlugin
      end

      # [5.143 OID_t](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/cbc2b761-8938-4591-a9f7-2d1512ed7f05)
      class OidT < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32         :oid_length, initial_value: -> { elements.max_count }
        drs_byte_array_ptr :elements
      end

      # [5.154 PrefixTableEntry](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/d26d36cd-10c4-4b27-a84e-98336abf357a)
      class PrefixTableEntry < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32 :ndx
        oid_t      :prefix
      end

      class PrefixTableEntryArrayPtr < Ndr::NdrConfArray
        default_parameter type: :prefix_table_entry
        extend Ndr::PointerClassPlugin
      end

      # [5.180 SCHEMA_PREFIX_TABLE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/9b371267-e8b8-4c69-9979-02dae02e5e38)
      class SchemaPrefixTable < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32                   :prefix_count, initial_value: -> { p_prefix_entry.max_count }
        prefix_table_entry_array_ptr :p_prefix_entry
      end

      class DrsConfStringz < Ndr::NdrConfArray
        extend Ndr::ArrayClassPlugin
        default_parameters type: :ndr_char
      end

      # [5.132 MTX_ADDR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/107b7c0e-0f0d-4fe2-8232-14ec3b78f40d)
      class MtxAddr < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32       :mtx_name_len, initial_value: -> { mtx_name.length }
        drs_conf_stringz :mtx_name
      end

      class MtxAddrPtr < MtxAddr
        default_parameters referent_byte_align: 4
        extend Ndr::PointerClassPlugin
      end

      # [5.219 VAR_SIZE_BUFFER_WITH_VERSION](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/589574c1-eaa1-456f-ac53-de597b2cff6b)
      class VarSizeBufferWithVersion < Ndr::NdrStruct
        default_parameter byte_align: 8

        ndr_uint32     :ul_version
        ndr_uint32     :cb_byte_buffer, initial_value: -> { rg_buffer.size }
        ndr_uint64     :ul_padding
        ndr_conf_array :rg_buffer, type: :ndr_uint8
      end

      class VarSizeBufferWithVersionPtr < VarSizeBufferWithVersion
        default_parameters referent_byte_align: 8
        extend Ndr::PointerClassPlugin
      end

      # [5.16 ATTRVAL](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/cc002cbf-efe0-42f8-9295-a5a6577263d4)
      class Attrval < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32         :val_len, initial_value: -> { p_val.length }
        drs_byte_array_ptr :p_val
      end

      class AttrvalArrayPtr < Ndr::NdrConfArray
        default_parameters type: :attrval
        extend Ndr::PointerClassPlugin
      end

      # [5.17 ATTRVALBLOCK](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b526370f-dfe5-4e85-9041-90d07bc16ff5)
      class Attrvalblock < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32        :val_count, initial_value: -> { p_aval.length }
        attrval_array_ptr :p_aval
      end

      # [5.9 ATTR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/a2db41e2-7803-4d3c-a499-0fee92b1c149)
      class Attr < Ndr::NdrStruct
        default_parameter byte_align: 4

        attrtyp      :attr_typ
        attrvalblock :attr_val
      end

      class AttrArrayPtr < Ndr::NdrConfArray
        default_parameters type: :attr
        extend Ndr::PointerClassPlugin
      end

      # [5.10 ATTRBLOCK](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f81324b8-6400-41b5-bc25-5117589c602a)
      class Attrblock < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32     :attr_count, initial_value: -> { p_attr.length }
        attr_array_ptr :p_attr
      end

      # [5.53 ENTINF](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/6d69822e-adb6-4977-8553-c2d529c17e5b)
      class Entinf < Ndr::NdrStruct
        default_parameter byte_align: 4

        ds_name_ptr :p_name
        ndr_uint32  :ul_flags
        attrblock   :attr_block
      end

      # [5.51 DSTIME](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/a72a16b9-73e4-41ca-a5c1-afc5fc54e175)
      class Dstime < BinData::Int64le
        default_parameter byte_align: 8
      end

      # [5.155 PROPERTY_META_DATA_EXT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/aef7ebde-c305-4224-95fd-585c86b19c38)
      class PropertyMetaDataExt < Ndr::NdrStruct
        default_parameter byte_align: 8

        ndr_uint32 :dw_version
        dstime     :time_changed
        uuid       :uuid_dsa_originating
        usn        :usn_originating
      end

      # [5.156 PROPERTY_META_DATA_EXT_VECTOR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/22bccd51-1e7d-4502-aef8-b84da983f94f)
      class PropertyMetaDataExtVector < Ndr::NdrStruct
        default_parameter byte_align: 8

        ndr_uint32     :c_num_props, initial_value: -> { rg_meta_data.size }
        ndr_conf_array :rg_meta_data, type: :property_meta_data_ext
      end

      class PropertyMetaDataExtVectorPtr < PropertyMetaDataExtVector
        default_parameters referent_byte_align: 8
        extend Ndr::PointerClassPlugin
      end

      # [5.162 REPLENTINFLIST](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/c38b0412-cf00-4b0c-b4f4-4662a4484a00)
      class ReplentinflistPtr < Ndr::NdrStruct
        default_parameters byte_align: 4, referent_byte_align: 4
        extend Ndr::PointerClassPlugin

        replentinflist_ptr                :p_next_ent_inf
        entinf                            :entinf
        ndr_boolean                       :f_is_nc_prefix
        uuid_ptr                          :p_parent_guid
        property_meta_data_ext_vector_ptr :p_meta_data_ext
      end

      # [4.1.10.2.19 DRS_COMPRESSED_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/6d3e7f57-3ef8-46e0-a6ad-e9331f297957)
      class DrsCompressedBlob < Ndr::NdrStruct
        default_parameter byte_align: 4

        ndr_uint32     :cb_uncompressed_size
        ndr_uint32     :cb_compressed_size
        ndr_conf_array :pb_compressed_data, type: :ndr_uint8
      end

      # [5.215 VALUE_META_DATA_EXT_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/7530cf2e-a2ad-4716-a570-8383f8b1846f)
      class ValueMetaDataExtV1 < Ndr::NdrStruct
        default_parameter byte_align: 8

        dstime                 :time_created
        property_meta_data_ext :meta_data
      end

      # [5.167 REPLVALINF_V1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/22946fbf-170e-4ab4-82c7-dabdfd97bf5a)
      class ReplvalinfV1 < Ndr::NdrStruct
        default_parameter byte_align: 8

        ds_name_ptr            :p_object
        attrtyp                :attr_typ
        attrval                :aval
        ndr_boolean            :f_is_present
        value_meta_data_ext_v1 :meta_data
      end

      class ReplvalinfV1ArrayPtr < Ndr::NdrConfArray
        default_parameters type: :replvalinf_v1
        extend Ndr::PointerClassPlugin
      end

      # [4.1.10.2.18 DRS_COMP_ALG_TYPE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/bb303730-0667-49f0-b117-288404c4b4cb)
      class DrsCompAlgType < Ndr::NdrUint32; end

      # [5.216 VALUE_META_DATA_EXT_V3](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/eab72899-a828-427d-8384-9a51ffdb77e1)
      class ValueMetaDataExtV3 < Ndr::NdrStruct
        default_parameter byte_align: 8

        dstime                 :time_created
        property_meta_data_ext :meta_data
        ndr_uint32             :unused1
        ndr_uint32             :unused2
        ndr_uint32             :unused3
        dstime                 :time_expired
      end

      # [5.168 REPLVALINF_V3](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/9c15369b-b7d2-437a-b73d-66a92c367795)
      class ReplvalinfV3 < Ndr::NdrStruct
        default_parameter byte_align: 8

        ds_name_ptr            :p_object
        attrtyp                :attr_typ
        attrval                :aval
        ndr_boolean            :f_is_present
        value_meta_data_ext_v3 :meta_data
      end

      class ReplvalinfV3ArrayPtr < Ndr::NdrConfArray
        default_parameters type: :replvalinf_v3
        extend Ndr::PointerClassPlugin
      end

      # [5.203 UPTODATE_CURSOR_V2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/d3e30021-b6ac-413e-b08a-b69b9b0c6592)
      class UptodateCursorV2 < Ndr::NdrStruct
        default_parameter byte_align: 8

        uuid   :uuid_dsa
        usn    :usn_high_prop_update
        dstime :time_last_sync_success
      end

      #[5.205 UPTODATE_VECTOR_V2_EXT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/cebd1ccb-891b-4268-b056-4b714cdf981e)
      class UptodateVectorV2Ext < Ndr::NdrStruct
        default_parameter byte_align: 8

        ndr_uint32     :dw_version
        ndr_uint32     :dw_reserved1
        ndr_uint32     :c_num_cursors
        ndr_uint32     :dw_reserved2
        ndr_conf_array :rg_cursors, type: :uptodate_cursor_v2
      end

      class UptodateVectorV2ExtPtr < UptodateVectorV2Ext
        default_parameters referent_byte_align: 8
        extend Ndr::PointerClassPlugin
      end


      require 'ruby_smb/dcerpc/drsr/drs_extensions'
      require 'ruby_smb/dcerpc/drsr/drs_bind_request'
      require 'ruby_smb/dcerpc/drsr/drs_bind_response'
      require 'ruby_smb/dcerpc/drsr/drs_unbind_request'
      require 'ruby_smb/dcerpc/drsr/drs_unbind_response'
      require 'ruby_smb/dcerpc/drsr/drs_domain_controller_info_request'
      require 'ruby_smb/dcerpc/drsr/drs_domain_controller_info_response'
      require 'ruby_smb/dcerpc/drsr/drs_crack_names_request'
      require 'ruby_smb/dcerpc/drsr/drs_crack_names_response'
      require 'ruby_smb/dcerpc/drsr/drs_get_nc_changes_request'
      require 'ruby_smb/dcerpc/drsr/drs_get_nc_changes_response'


      # Creates a context handle that is necessary to call any other method in this interface
      #
      # @return [RubySMB::Dcerpc::Drsr::DrsHandle] Context handle
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #   DrsBind packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #   is not STATUS_SUCCESS
      def drs_bind
        drs_extensions_int = DrsExtensionsInt.new(
          dw_flags: DRS_EXT_GETCHGREQ_V6 | DRS_EXT_GETCHGREPLY_V6 | DRS_EXT_GETCHGREQ_V8 | DRS_EXT_STRONG_ENCRYPTION,
          dw_ext_caps: 0xFFFFFFFF
        )
        drs_bind_request = DrsBindRequest.new(pext_client: drs_extensions_int)
        response = dcerpc_request(
          drs_bind_request,
          auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
          auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
        )
        begin
          drs_bind_response = DrsBindResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading DrsBindResponse'
        end
        unless drs_bind_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::DrsrError,
            "Error returned with drs_bind: "\
            "#{WindowsError::NTStatus.find_by_retval(drs_bind_response.error_status.value).join(',')}"
        end

        ppext_server = drs_bind_response.ppext_server
        raw_drs_extensions_int = ppext_server.cb.to_binary_s + ppext_server.rgb.to_binary_s
        drs_extensions_int_response = DrsExtensionsInt.new
        # If dwExtCaps is not included, just add zeros to parse it correctly
        raw_drs_extensions_int << "\x00".b * (drs_extensions_int.num_bytes - ppext_server.cb)
        drs_extensions_int_response.read(raw_drs_extensions_int)

        unless drs_extensions_int_response.dw_repl_epoch == 0
          # Different epoch, we have to call DRSBind again
          drs_extensions_int.dw_repl_epoch = drs_extensions_int_response.dw_repl_epoch
          drs_bind_request.pext_client.assign(drs_extensions_int)
          response = dcerpc_request(
            drs_bind_request,
            auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
          )
          begin
            drs_bind_response = DrsBindResponse.read(response)
          rescue IOError
            raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading DrsBindResponse'
          end
          unless drs_bind_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
            raise RubySMB::Dcerpc::Error::DrsrError,
              "Error returned with drs_bind: "\
              "#{WindowsError::NTStatus.find_by_retval(drs_bind_response.error_status.value).join(',')}"
          end
        end

        drs_bind_response.ph_drs
      end

      # Destroys a context handle previously created by the #drs_bind method
      #
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #   DrsUnbind packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #   is not STATUS_SUCCESS
      def drs_unbind(ph_drs)
        drs_unbind_request = DrsUnbindRequest.new(ph_drs: ph_drs)
        response = dcerpc_request(
          drs_unbind_request,
          auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
          auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
        )
        begin
          drs_unbind_response = DrsUnbindResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading DrsUnbindResponse'
        end
        unless drs_unbind_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::DrsrError,
            "Error returned with drs_unbind: "\
            "#{WindowsError::NTStatus.find_by_retval(drs_unbind_response.error_status.value).join(',')}"
        end

        nil
      end

      # Retrieves information about DCs in a given domain
      #
      # @param h_drs [RubySMB::Dcerpc::Drsr::DrsHandle] Context handle
      #   previously created by the #drs_bind method
      # @param domain [String] Domain name
      # @return [Array<RubySMB::Dcerpc::Drsr::DsDomainControllerInfo1wPtr>]
      #   Array of DsDomainControllerInfo1wPtr containing information about DCs
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #   DrsDomainControllerInfo packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #   is not STATUS_SUCCESS
      def drs_domain_controller_info(h_drs, domain)
        drs_domain_controller_info_request = DrsDomainControllerInfoRequest.new(
          h_drs: h_drs,
          pmsg_in: {
            switch_type: 1,
            msg_dcinfo: {
              domain: domain,
              info_level: 2
            }
          }
        )
        response = dcerpc_request(
          drs_domain_controller_info_request,
          auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
          auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
        )
        begin
          drs_domain_controller_info_response = DrsDomainControllerInfoResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading DrsDomainControllerInfoResponse'
        end
        unless drs_domain_controller_info_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::DrsrError,
            "Error returned with drs_domain_controller_info: "\
            "#{WindowsError::NTStatus.find_by_retval(drs_domain_controller_info_response.error_status.value).join(',')}"
        end

        drs_domain_controller_info_response.pmsg_out.msg_dcinfo.r_items.to_ary
      end

      # Looks up each of a set of objects in the directory and returns it to
      # the caller in the requested format
      #
      # @param h_drs [RubySMB::Dcerpc::Drsr::DrsHandle] Context handle
      #   previously created by the #drs_bind method
      # @param flags [Integer] Flags (see `DRS_MSG_CRACKREQ_V1 dwFlags` in this
      #   file)
      # @param format_offered [Integer] The format of the names in rp_names
      #   (see DS_NAME_FORMAT constants in this file )
      # @param format_desired [Integer] The format of the names returned
      #   (see DS_NAME_FORMAT constants in this file )
      # @param rp_names [Array<String>] Input names to translate
      # @return [Array<RubySMB::Dcerpc::Drsr::DsNameResultItemwPtr>]
      #   Array of DsNameResultItemwPtr containing the translated names
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #   DrsCrackNames packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #   is not STATUS_SUCCESS
      def drs_crack_names(h_drs, flags: 0, format_offered: DS_SID_OR_SID_HISTORY_NAME, format_desired: DS_UNIQUE_ID_NAME, rp_names: [])
        drs_crack_names_request = DrsCrackNamesRequest.new(
          h_drs: h_drs,
          pmsg_in: {
            switch_type: 1,
            msg_crack: {
              dw_flags: flags,
              format_offered: format_offered,
              format_desired: format_desired,
              rp_names: rp_names
            }
          }
        )
        response = dcerpc_request(
          drs_crack_names_request,
          auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
          auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
        )
        begin
          drs_crack_names_response = DrsCrackNamesResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading DrsCrackNamesResponse'
        end
        unless drs_crack_names_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::DrsrError,
            "Error returned with drs_crack_names: "\
            "#{WindowsError::NTStatus.find_by_retval(drs_crack_names_response.error_status.value).join(',')}"
        end

        drs_crack_names_response.pmsg_out.msg_crack.p_result.r_items.to_ary
      end

      # [4.1.10.2.20 ENCRYPTED_PAYLOAD](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/7b60d2b3-5bb1-49aa-aefc-fa887e683977)
      class EncryptedPayload < BinData::Record
        endian :little

        uint8_array :salt, initial_length: 16
        uint32      :check_sum
        uint8_array :encrypted_data, read_until: :eof
      end

      # [4.1.10.6.17 DecryptValuesIfNecessary](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/a14e34f0-69ff-484e-820c-1170c63c19ab)
      def decrypt_attribute_value(attribute)
        unless @session_key
          raise RubySMB::Error::EncryptionError, 'Unable to decrypt attribute value: session key is empty'
        end
        encrypted_payload = EncryptedPayload.read(attribute)

        signature = OpenSSL::Digest::MD5.digest(@session_key + encrypted_payload.salt.to_binary_s)
        rc4 = OpenSSL::Cipher.new('rc4')
        rc4.decrypt
        rc4.key = signature
        plain_text = rc4.update(
          encrypted_payload.check_sum.to_binary_s +
          encrypted_payload.encrypted_data.to_binary_s
        )
        plain_text += rc4.final

        plain_text[4..-1]
      end

      # From [MS-LSAD] [5.1.3 DES-ECB-LM Cipher Definition](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/32a2c8af-dc6e-4662-918d-ef333d570dd2)
      def transform_key(input_key)
        output_key = []
        output_key << (input_key[0].ord >> 0x01).chr
        output_key << (((input_key[0].ord & 0x01) << 6) | (input_key[1].ord >> 2)).chr
        output_key << (((input_key[1].ord & 0x03) << 5) | (input_key[2].ord >> 3)).chr
        output_key << (((input_key[2].ord & 0x07) << 4) | (input_key[3].ord >> 4)).chr
        output_key << (((input_key[3].ord & 0x0F) << 3) | (input_key[4].ord >> 5)).chr
        output_key << (((input_key[4].ord & 0x1F) << 2) | (input_key[5].ord >> 6)).chr
        output_key << (((input_key[5].ord & 0x3F) << 1) | (input_key[6].ord >> 7)).chr
        output_key << (input_key[6].ord & 0x7F).chr

        output_key.map { |byte| ((byte.ord << 1) & 0xFE).chr }.join
      end

      # From [MS-SAMR] [2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b1b0094f-2546-431f-b06d-582158a9f2bb)
      def derive_key(base_key)
        key = [base_key].pack('L<')
        key1 = [key[0] , key[1] , key[2] , key[3] , key[0] , key[1] , key[2]]
        key2 = [key[3] , key[0] , key[1] , key[2] , key[3] , key[0] , key[1]]
        [transform_key(key1.join), transform_key(key2.join)]
      end

      def remove_des_layer(crypted_hash, rid)
        key1, key2 = derive_key(rid)

        des = OpenSSL::Cipher.new('des-ecb')
        des.decrypt
        des.key = key1
        des.padding = 0
        decrypted_hash = des.update(crypted_hash[0,8])
        decrypted_hash += des.final

        des.reset
        des.decrypt
        des.key = key2
        des.padding = 0
        decrypted_hash += des.update(crypted_hash[8..-1])
        decrypted_hash += des.final

        decrypted_hash
      end

      # Replicates updates from an NC replica on the server
      #
      # @param h_drs [RubySMB::Dcerpc::Drsr::DrsHandle] Context handle
      #   previously created by the #drs_bind method
      # @param nc_guid [String] GUID of the DSName representing the NC
      #   (naming context) root of the replica to replicate
      # @param nc_guid [String] DSA GUID of the DC.
      # @return [RubySMB::Dcerpc::Drsr::DrsGetNcChangesResponse] Response
      #   structure containing the updates
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #   DrsGetNcChanges packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #   is not STATUS_SUCCESS
      def drs_get_nc_changes(h_drs, nc_guid:, dsa_object_guid:)
        drs_get_nc_changes_request = DrsGetNcChangesRequest.new(
          h_drs: h_drs,
          dw_in_version: 8,
          pmsg_in: {
            msg_getchg: {
              uuid_dsa_obj_dest: dsa_object_guid,
              uuid_invoc_id_src: dsa_object_guid,
              p_nc: {
                guid: nc_guid,
                string_name: ["\0"]
              },
              ul_flags: DRS_INIT_SYNC | DRS_WRIT_REP,
              c_max_objects: 1,
              ul_extended_op: EXOP_REPL_OBJ
            }
          }
        )

        ATTRTYP_TO_ATTID.values.each do |oid|
          drs_get_nc_changes_request.pmsg_in.msg_getchg.add_attrtyp_from_oid(oid)
        end

        response = dcerpc_request(
          drs_get_nc_changes_request,
          auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
          auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
        )
        begin
          drs_get_nc_changes_response = DrsGetNcChangesResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading DrsGetNcChangesResponse'
        end
        unless drs_get_nc_changes_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::DrsrError,
            "Error returned with drs_get_nc_changes: "\
            "#{WindowsError::NTStatus.find_by_retval(drs_get_nc_changes_response.error_status.value).join(',')}"
        end

        drs_get_nc_changes_response
      end

    end
  end
end

