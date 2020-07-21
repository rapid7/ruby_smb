module RubySMB
  module Dcerpc
    module Winreg

      UUID = '338CD001-2244-31F1-AAAA-900038001003'
      VER_MAJOR = 1
      VER_MINOR = 0

      # Operation numbers
      OPEN_HKCR             = 0x00
      OPEN_HKCU             = 0x01
      OPEN_HKLM             = 0x02
      OPEN_HKPD             = 0x03
      OPEN_HKU              = 0x04
      REG_CLOSE_KEY         = 0x05
      REG_CREATE_KEY        = 0x06
      REG_ENUM_KEY          = 0x09
      REG_ENUM_VALUE        = 0x0a
      REG_OPEN_KEY          = 0x0f
      REG_QUERY_INFO_KEY    = 0x10
      REG_QUERY_VALUE       = 0x11
      REG_SAVE_KEY          = 0x14
      OPEN_HKCC             = 0x1b
      OPEN_HKPT             = 0x20
      OPEN_HKPN             = 0x21

      require 'ruby_smb/dcerpc/winreg/regsam'
      require 'ruby_smb/dcerpc/winreg/open_root_key_request'
      require 'ruby_smb/dcerpc/winreg/open_root_key_response'
      require 'ruby_smb/dcerpc/winreg/close_key_request'
      require 'ruby_smb/dcerpc/winreg/close_key_response'
      require 'ruby_smb/dcerpc/winreg/enum_key_request'
      require 'ruby_smb/dcerpc/winreg/enum_key_response'
      require 'ruby_smb/dcerpc/winreg/enum_value_request'
      require 'ruby_smb/dcerpc/winreg/enum_value_response'
      require 'ruby_smb/dcerpc/winreg/open_key_request'
      require 'ruby_smb/dcerpc/winreg/open_key_response'
      require 'ruby_smb/dcerpc/winreg/query_info_key_request'
      require 'ruby_smb/dcerpc/winreg/query_info_key_response'
      require 'ruby_smb/dcerpc/winreg/query_value_request'
      require 'ruby_smb/dcerpc/winreg/query_value_response'
      require 'ruby_smb/dcerpc/winreg/create_key_request'
      require 'ruby_smb/dcerpc/winreg/create_key_response'
      require 'ruby_smb/dcerpc/winreg/save_key_request'
      require 'ruby_smb/dcerpc/winreg/save_key_response'

      ROOT_KEY_MAP = {
        "HKEY_CLASSES_ROOT"         => OPEN_HKCR,
        "HKCR"                      => OPEN_HKCR,
        "HKEY_CURRENT_USER"         => OPEN_HKCU,
        "HKCU"                      => OPEN_HKCU,
        "HKEY_LOCAL_MACHINE"        => OPEN_HKLM,
        "HKLM"                      => OPEN_HKLM,
        "HKEY_PERFORMANCE_DATA"     => OPEN_HKPD,
        "HKPD"                      => OPEN_HKPD,
        "HKEY_USERS"                => OPEN_HKU,
        "HKU"                       => OPEN_HKU,
        "HKEY_CURRENT_CONFIG"       => OPEN_HKCC,
        "HKCC"                      => OPEN_HKCC,
        "HKEY_PERFORMANCE_TEXT"     => OPEN_HKPT,
        "HKPT"                      => OPEN_HKPT,
        "HKEY_PERFORMANCE_NLS_TEXT" => OPEN_HKPN,
        "HKPN"                      => OPEN_HKPN
      }

      # Open the registry root key and return a handle for it. The key can be
      # either a long format (e.g. HKEY_LOCAL_MACHINE) or a short format
      # (e.g. HKLM)
      #
      # @param root_key [String] the root key to open
      # @return [Ndr::NdrContextHandle] the RPC context handle for the root key
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a OpenRootKeyResponse packet
      # @raise [RubySMB::Dcerpc::Error::WinregError] if the response error status is not ERROR_SUCCESS
      def open_root_key(root_key)
        root_key_opnum = RubySMB::Dcerpc::Winreg::ROOT_KEY_MAP[root_key]
        raise ArgumentError, "Unknown Root Key: #{root_key}" unless root_key_opnum

        root_key_request_packet = OpenRootKeyRequest.new(opnum: root_key_opnum)
        response = dcerpc_request(root_key_request_packet)

        begin
          root_key_response_packet = OpenRootKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket,
            "Error reading OpenRootKeyResponse (command = #{root_key_opnum})"
        end
        unless root_key_response_packet.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError,
            "Error returned when opening root key #{root_key}: "\
            "#{WindowsError::Win32.find_by_retval(root_key_response_packet.error_status.value).join(',')}"
        end

        root_key_response_packet.ph_key
      end

      # Open the registry key specified by a root key handle (previously open
      # with #open_root_key) and a subkey. It returns a handle for the key.
      #
      # @param handle [Ndr::NdrContextHandle] the handle for the root key
      # @param sub_key [String] the subkey to open
      # @return [Ndr::NdrContextHandle] the RPC context handle for the key
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a OpenKeyResponse packet
      # @raise [RubySMB::Dcerpc::Error::WinregError] if the response error status is not ERROR_SUCCESS
      def open_key(handle, sub_key)
        openkey_request_packet = RubySMB::Dcerpc::Winreg::OpenKeyRequest.new(hkey: handle, lp_sub_key: sub_key)
        openkey_request_packet.sam_desired.read_control = 1
        openkey_request_packet.sam_desired.key_query_value = 1
        openkey_request_packet.sam_desired.key_enumerate_sub_keys = 1
        openkey_request_packet.sam_desired.key_notify = 1
        response = dcerpc_request(openkey_request_packet)
        begin
          open_key_response = RubySMB::Dcerpc::Winreg::OpenKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the OpenKey response"
        end
        unless open_key_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when opening subkey #{sub_key}: "\
            "#{WindowsError::Win32.find_by_retval(open_key_response.error_status.value).join(',')}"
        end

        open_key_response.phk_result
      end

      # Retrieve the data associated with the named value of a specified
      # registry open key.
      #
      # @param handle [Ndr::NdrContextHandle] the handle for the key
      # @param value_name [String] the name of the value
      # @return [String] the data of the value entry
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a QueryValueResponse packet
      # @raise [RubySMB::Dcerpc::Error::WinregError] if the response error status is not ERROR_SUCCESS
      def query_value(handle, value_name)
        query_value_request_packet = RubySMB::Dcerpc::Winreg::QueryValueRequest.new(hkey: handle, lp_value_name: value_name)
        query_value_request_packet.lp_type = 0
        query_value_request_packet.lpcb_data = 0
        query_value_request_packet.lpcb_len = 0
        response = dcerpc_request(query_value_request_packet)
        begin
          query_value_response = RubySMB::Dcerpc::Winreg::QueryValueResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the QueryValue response"
        end
        unless query_value_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when reading value #{value_name}: "\
            "#{WindowsError::Win32.find_by_retval(query_value_response.error_status.value).join(',')}"
        end

        query_value_request_packet.lpcb_data = query_value_response.lpcb_data
        query_value_request_packet.lp_data = []
        query_value_request_packet.lp_data.referent.max_count = query_value_response.lpcb_data.referent
        response = dcerpc_request(query_value_request_packet)
        begin
          query_value_response = RubySMB::Dcerpc::Winreg::QueryValueResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the QueryValue response"
        end
        unless query_value_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when reading value #{value_name}: "\
            "#{WindowsError::Win32.find_by_retval(query_value_response.error_status.value).join(',')}"
        end

        query_value_response.data
      end

      # Close the handle to the registry key.
      #
      # @param handle [Ndr::NdrContextHandle] the handle for the key
      # @return [WindowsError::Win32] the response error status
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a CloseKeyResponse packet
      # @raise [RubySMB::Dcerpc::Error::WinregError] if the response error status is not ERROR_SUCCESS
      def close_key(handle)
        close_key_request_packet = RubySMB::Dcerpc::Winreg::CloseKeyRequest.new(hkey: handle)
        response = dcerpc_request(close_key_request_packet)
        begin
          close_key_response = RubySMB::Dcerpc::Winreg::CloseKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the CloseKey response"
        end
        unless close_key_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when closing the key: "\
            "#{WindowsError::Win32.find_by_retval(close_key_response.error_status.value).join(',')}"
        end

        close_key_response.error_status
      end

      # Retrive relevant information on the key that corresponds to the
      # specified key handle.
      #
      # @param handle [Ndr::NdrContextHandle] the handle for the key
      # @return [RubySMB::Dcerpc::Winreg::QueryInfoKeyResponse] the QueryInfoKeyResponse packet
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a QueryInfoKeyResponse packet
      # @raise [RubySMB::Dcerpc::Error::WinregError] if the response error status is not ERROR_SUCCESS
      def query_info_key(handle)
        query_info_key_request_packet = RubySMB::Dcerpc::Winreg::QueryInfoKeyRequest.new(hkey: handle)
        query_info_key_request_packet.lp_class = ''
        query_info_key_request_packet.lp_class.referent.actual_count = 0
        query_info_key_request_packet.lp_class.maximum_length = 1024
        query_info_key_request_packet.lp_class.buffer.referent.max_count = 1024 / 2
        response = dcerpc_request(query_info_key_request_packet)
        begin
          query_info_key_response = RubySMB::Dcerpc::Winreg::QueryInfoKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the query_infoKey response"
        end
        unless query_info_key_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when querying information: "\
            "#{WindowsError::Win32.find_by_retval(query_info_key_response.error_status.value).join(',')}"
        end

        query_info_key_response
      end

      # Enumerate the subkey at the specified index.
      #
      # @param handle [Ndr::NdrContextHandle] the handle for the key
      # @param index [Numeric] the index of the subkey
      # @return [String] the subkey name
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a EnumKeyResponse packet
      # @raise [RubySMB::Dcerpc::Error::WinregError] if the response error status is not ERROR_SUCCESS
      def enum_key(handle, index)
        enum_key_request_packet = RubySMB::Dcerpc::Winreg::EnumKeyRequest.new(hkey: handle, dw_index: index)
        enum_key_request_packet.lpft_last_write_time = 0
        enum_key_request_packet.lp_class = 0
        enum_key_request_packet.lp_name.buffer.referent.max_count = 256
        response = dcerpc_request(enum_key_request_packet)
        begin
          enum_key_response = RubySMB::Dcerpc::Winreg::EnumKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the EnumKey response"
        end
        unless enum_key_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when enumerating the key: "\
            "#{WindowsError::Win32.find_by_retval(enum_key_response.error_status.value).join(',')}"
        end

        enum_key_response.lp_name.to_s
      end

      # Enumerate the value at the specified index for the specified registry key.
      #
      # @param handle [Ndr::NdrContextHandle] the handle for the key
      # @param index [Numeric] the index of the subkey
      # @return [String] the data of the value entry
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a EnumValueResponse packet
      # @raise [RubySMB::Dcerpc::Error::WinregError] if the response error status is not ERROR_SUCCESS
      def enum_value(handle, index)
        enum_value_request_packet = RubySMB::Dcerpc::Winreg::EnumValueRequest.new(hkey: handle, dw_index: index)
        enum_value_request_packet.lp_data.referent_identifier = 0
        enum_value_request_packet.lp_value_name.buffer.referent.max_count = 256
        response = dcerpc_request(enum_value_request_packet)
        begin
          enum_value_response = RubySMB::Dcerpc::Winreg::EnumValueResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the Enumvalue response"
        end
        unless enum_value_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when enumerating values: "\
            "#{WindowsError::Win32.find_by_retval(enum_value_response.error_status.value).join(',')}"
        end

        enum_value_response.lp_value_name.to_s
      end

      # Creates the specified registry key and returns a handle to the newly created key
      #
      # @param handle [Ndr::NdrContextHandle] the handle for the key
      # @param sub_key [String] the name of the key
      # @param opts [Hash] options for the CreateKeyRequest
      # @return [RubySMB::Dcerpc::Winreg::PrpcHkey] the handle to the opened or created key
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a CreateKeyResponse packet
      # @raise [RubySMB::Dcerpc::Error::WinregError] if the response error status is not ERROR_SUCCESS
      def create_key(handle, sub_key, opts = {})
        opts = {
          hkey:                   handle,
          lp_sub_key:             sub_key,
          lp_class:               opts[:lp_class] || :null,
          dw_options:             opts[:dw_options] || RubySMB::Dcerpc::Winreg::CreateKeyRequest::REG_KEY_TYPE_VOLATILE,
          sam_desired:            opts[:sam_desired] || RubySMB::Dcerpc::Winreg::Regsam.new(maximum: 1),
          lp_security_attributes: opts[:lp_security_attributes] || RubySMB::Dcerpc::RpcSecurityAttributes.new,
          lpdw_disposition:       opts[:lpdw_disposition] || RubySMB::Dcerpc::Winreg::CreateKeyRequest::REG_CREATED_NEW_KEY,
        }
        create_key_request_packet = RubySMB::Dcerpc::Winreg::CreateKeyRequest.new(opts)
        response = dcerpc_request(create_key_request_packet)
        begin
          create_key_response = RubySMB::Dcerpc::Winreg::CreateKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the CreateKey response"
        end
        unless create_key_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when creating key #{sub_key}: "\
            "#{WindowsError::Win32.find_by_retval(create_key_response.error_status.value).join(',')}"
        end

        create_key_response.hkey
      end

      # Saves the specified key, subkeys, and values to a new file
      #
      # @param handle [Ndr::NdrContextHandle] the handle for the key
      # @param file_name [String] the name of the registry file in which the specified key and subkeys are to be saved
      # @param opts [Hash] options for the SaveKeyRequest
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a SaveKeyResponse packet
      # @raise [RubySMB::Dcerpc::Error::WinregError] if the response error status is not ERROR_SUCCESS
      def save_key(handle, file_name, opts = {})
        opts = {
          hkey:                   handle,
          lp_file:                file_name,
          lp_security_attributes: opts[:lp_security_attributes] || :null,
        }
        save_key_request_packet = RubySMB::Dcerpc::Winreg::SaveKeyRequest.new(opts)
        response = dcerpc_request(save_key_request_packet)
        begin
          save_key_response = RubySMB::Dcerpc::Winreg::SaveKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the SaveKeyResponse response"
        end
        unless save_key_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when saving key to #{file_name}: "\
            "#{WindowsError::Win32.find_by_retval(save_key_response.error_status.value).join(',')}"
        end
      end

      # Checks if the specified registry key exists. It returns true if it
      # exists, false otherwise.
      #
      # @param key [String] the registry key to check
      # @return [Boolean]
      def has_registry_key?(key, bind: true)
        bind(endpoint: RubySMB::Dcerpc::Winreg) if bind

        root_key, sub_key = key.gsub(/\//, '\\').split('\\', 2)
        begin
          root_key_handle = open_root_key(root_key)
          subkey_handle = open_key(root_key_handle, sub_key)
        rescue RubySMB::Dcerpc::Error::WinregError
          return false
        end
        return true
      ensure
        close_key(subkey_handle) if subkey_handle
        close_key(root_key_handle) if root_key_handle
      end

      # Retrieve the data associated with the named value of a specified
      # registry key.
      #
      # @param key [String] the registry key
      # @param value_name [String] the name of the value to read
      # @return [String] the data of the value entry
      def read_registry_key_value(key, value_name, bind: true)
        bind(endpoint: RubySMB::Dcerpc::Winreg) if bind

        root_key, sub_key = key.gsub(/\//, '\\').split('\\', 2)
        root_key_handle = open_root_key(root_key)
        subkey_handle = open_key(root_key_handle, sub_key)
        value = query_value(subkey_handle, value_name)
        value
      ensure
        close_key(subkey_handle) if subkey_handle
        close_key(root_key_handle) if root_key_handle
      end

      # Enumerate the subkeys of a specified registry key. If only a root key
      # is provided, it enumerates its subkeys.
      #
      # @param key [String] the registry key
      # @return [Array<String>] the subkeys
      def enum_registry_key(key, bind: true)
        bind(endpoint: RubySMB::Dcerpc::Winreg) if bind

        root_key, sub_key = key.gsub(/\//, '\\').split('\\', 2)
        root_key_handle = open_root_key(root_key)
        subkey_handle = if sub_key.nil? || sub_key.empty?
                          root_key_handle
                        else
                          open_key(root_key_handle, sub_key)
                        end
        query_info_key_response = query_info_key(subkey_handle)
        key_count = query_info_key_response.lpc_sub_keys.to_i
        enum_result = []
        key_count.times do |i|
          enum_result << enum_key(subkey_handle, i)
        end
        enum_result
      ensure
        close_key(subkey_handle) if subkey_handle
        close_key(root_key_handle) if root_key_handle
      end

      # Enumerate the values for the specified registry key.
      #
      # @param key [String] the registry key
      # @return [Array<String>] the values
      def enum_registry_values(key, bind: true)
        bind(endpoint: RubySMB::Dcerpc::Winreg) if bind

        root_key, sub_key = key.gsub(/\//, '\\').split('\\', 2)
        root_key_handle = open_root_key(root_key)
        subkey_handle = if sub_key.nil? || sub_key.empty?
                          root_key_handle
                        else
                          open_key(root_key_handle, sub_key)
                        end
        query_info_key_response = query_info_key(subkey_handle)
        value_count = query_info_key_response.lpc_values.to_i
        enum_result = []
        value_count.times do |i|
          enum_result << enum_value(subkey_handle, i)
        end
        enum_result
      ensure
        close_key(subkey_handle) if subkey_handle
        close_key(root_key_handle) if root_key_handle
      end

    end
  end
end
