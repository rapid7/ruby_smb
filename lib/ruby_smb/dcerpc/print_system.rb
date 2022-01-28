module RubySMB
  module Dcerpc
    module PrintSystem

      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/848b8334-134a-4d02-aea4-03b673d6c515
      UUID = '12345678-1234-abcd-ef00-0123456789ab'.freeze
      VER_MAJOR = 1
      VER_MINOR = 0

      # Operation numbers
      RPC_ENUM_PRINTER_DRIVERS = 10
      RPC_GET_PRINTER_DRIVER_DIRECTORY = 12
      RPC_ADD_PRINTER_DRIVER_EX = 89

      # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b96cc497-59e5-4510-ab04-5484993b259b
      APD_STRICT_UPGRADE = 0x00000001
      APD_STRICT_DOWNGRADE = 0x00000002
      APD_COPY_ALL_FILES = 0x00000004
      APD_COPY_NEW_FILES = 0x00000008
      APD_COPY_FROM_DIRECTORY = 0x00000010
      APD_DONT_COPY_FILES_TO_CLUSTER = 0x00001000
      APD_COPY_TO_ALL_SPOOLERS = 0x00002000
      APD_INSTALL_WARNED_DRIVER = 0x00008000
      APD_RETURN_BLOCKING_STATUS_CODE = 0x00010000

      # [2.2.1.5.2 DRIVER_INFO_2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/39bbfc30-8768-4cd4-9930-434857e2c2a2)
      class DriverInfo2 < RubySMB::Dcerpc::Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32 :c_version
        ndr_wide_stringz_ptr :p_name
        ndr_wide_stringz_ptr :p_environment
        ndr_wide_stringz_ptr :p_driver_path
        ndr_wide_stringz_ptr :p_data_file
        ndr_wide_stringz_ptr :p_config_file
      end

      class PDriverInfo2 < DriverInfo2
        extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
      end

      # [2.2.1.2.3 DRIVER_CONTAINER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/3a3f9cf7-8ec4-4921-b1f6-86cf8d139bc2)
      class DriverContainer < RubySMB::Dcerpc::Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32 :level, check_value: -> { [2].include?(value) }
        ndr_uint32 :tag
        choice :driver_info, selection: :level, byte_align: 4 do
          p_driver_info2 2
        end
      end

      # for RpcEnumPrinterDrivers and RpcGetPrinterDriverDirectory `BYTE*` fields
      class RprnByteArrayPtr < RubySMB::Dcerpc::Ndr::NdrConfArray
        default_parameters type: :ndr_uint8
        extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
      end

      require 'ruby_smb/dcerpc/print_system/rpc_add_printer_driver_ex_request'
      require 'ruby_smb/dcerpc/print_system/rpc_add_printer_driver_ex_response'
      require 'ruby_smb/dcerpc/print_system/rpc_enum_printer_drivers_request'
      require 'ruby_smb/dcerpc/print_system/rpc_enum_printer_drivers_response'
      require 'ruby_smb/dcerpc/print_system/rpc_get_printer_driver_directory_request'
      require 'ruby_smb/dcerpc/print_system/rpc_get_printer_driver_directory_response'
    end
  end
end
