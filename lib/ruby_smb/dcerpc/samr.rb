module RubySMB
  module Dcerpc
    module Samr

      UUID = '12345778-1234-abcd-ef00-0123456789ac'
      VER_MAJOR = 1
      VER_MINOR = 0

      # Operation numbers
      SAMR_CONNECT = 0x0000
      SAMR_LOOKUP_DOMAIN_IN_SAM_SERVER = 0x0005
      SAMR_OPEN_DOMAIN = 0x0007
      SAMR_ENUMERATE_USERS_IN_DOMAIN = 0x000D
      SAMR_RID_TO_SID = 0x0041

      class SamprHandle < Ndr::NdrContextHandle; end


      #################################
      #           Constants           #
      #################################


      ################
      # ACCESS_MASK Values

      # Common Values
      # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/15b9ebf7-161d-4c83-a672-dceb2ac8c448

      # Specifies the ability to delete the object.
      DELETE                 = 0x00010000
      # Specifies the ability to read the security descriptor.
      READ_CONTROL           = 0x00020000
      # Specifies the ability to update the discretionary access control list
      # (DACL) of the security descriptor.
      WRITE_DAC              = 0x00040000
      # Specifies the ability to update the Owner field of the security
      # descriptor.
      WRITE_OWNER            = 0x00080000
      # Specifies access to the system security portion of the security
      # descriptor.
      ACCESS_SYSTEM_SECURITY = 0x01000000
      # Indicates that the caller is requesting the most access possible to the
      # object.
      MAXIMUM_ALLOWED        = 0x02000000


      # Server values
      # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e8afb15e-c053-4984-b84b-66877236e141

      # Specifies access control to obtain a server handle.
      SAM_SERVER_CONNECT           = 0x00000001
      # Does not specify any access control.
      SAM_SERVER_SHUTDOWN          = 0x00000002
      # Does not specify any access control.
      SAM_SERVER_INITIALIZE        = 0x00000004
      # Does not specify any access control.
      SAM_SERVER_CREATE_DOMAIN     = 0x00000008
      # Specifies access control to view domain objects.
      SAM_SERVER_ENUMERATE_DOMAINS = 0x00000010
      # Specifies access control to perform SID-to-name translation.
      SAM_SERVER_LOOKUP_DOMAIN     = 0x00000020
      # The specified accesses for a GENERIC_ALL request.
      SAM_SERVER_ALL_ACCESS        = 0x000F003F
      # The specified accesses for a GENERIC_READ request.
      SAM_SERVER_READ              = 0x00020010
      # The specified accesses for a GENERIC_WRITE request.
      SAM_SERVER_WRITE             = 0x0002000E
      # The specified accesses for a GENERIC_EXECUTE request.
      SAM_SERVER_EXECUTE           = 0x00020021

      # Domain values
      # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/aef23495-f6aa-48e9-aebc-22e022a2b4eb

      # Specifies access control to read password policy.
      DOMAIN_READ_PASSWORD_PARAMETERS = 0x00000001
      # Specifies access control to write password policy.
      DOMAIN_WRITE_PASSWORD_PARAMS    = 0x00000002
      # Specifies access control to read attributes not related to password
      # policy.
      DOMAIN_READ_OTHER_PARAMETERS    = 0x00000004
      # Specifies access control to write attributes not related to password
      # policy.
      DOMAIN_WRITE_OTHER_PARAMETERS   = 0x00000008
      # Specifies access control to create a user object.
      DOMAIN_CREATE_USER              = 0x00000010
      # Specifies access control to create a group object.
      DOMAIN_CREATE_GROUP             = 0x00000020
      # Specifies access control to create an alias object.
      DOMAIN_CREATE_ALIAS             = 0x00000040
      # Specifies access control to read the alias membership of a set of SIDs.
      DOMAIN_GET_ALIAS_MEMBERSHIP     = 0x00000080
      # Specifies access control to enumerate objects.
      DOMAIN_LIST_ACCOUNTS            = 0x00000100
      # Specifies access control to look up objects by name and SID.
      DOMAIN_LOOKUP                   = 0x00000200
      # Specifies access control to various administrative operations on the
      # server.
      DOMAIN_ADMINISTER_SERVER        = 0x00000400
      # The specified accesses for a GENERIC_ALL request.
      DOMAIN_ALL_ACCESS               = 0x000F07FF
      # The specified accesses for a GENERIC_READ request.
      DOMAIN_READ                     = 0x00020084
      # The specified accesses for a GENERIC_WRITE request.
      DOMAIN_WRITE                    = 0x0002047A
      # The specified accesses for a GENERIC_EXECUTE request.
      DOMAIN_EXECUTE                  = 0x00020301


      require 'ruby_smb/dcerpc/samr/user_account_control'
      require 'ruby_smb/dcerpc/samr/rpc_sid'

      require 'ruby_smb/dcerpc/samr/samr_connect_request'
      require 'ruby_smb/dcerpc/samr/samr_connect_response'
      require 'ruby_smb/dcerpc/samr/samr_lookup_domain_in_sam_server_request'
      require 'ruby_smb/dcerpc/samr/samr_lookup_domain_in_sam_server_response'
      require 'ruby_smb/dcerpc/samr/samr_open_domain_request'
      require 'ruby_smb/dcerpc/samr/samr_open_domain_response'
      require 'ruby_smb/dcerpc/samr/samr_enumerate_users_in_domain_request'
      require 'ruby_smb/dcerpc/samr/samr_enumerate_users_in_domain_response'
      require 'ruby_smb/dcerpc/samr/samr_rid_to_sid_request'
      require 'ruby_smb/dcerpc/samr/samr_rid_to_sid_response'

      # Returns a handle to a server object.
      #
      # @param server_name [Char] the first character of the NETBIOS name of
      #  the server (optional)
      # @param access [Numeric] access requested for ServerHandle upon output:
      #  bitwise OR of common and server ACCESS_MASK values (defined in
      #  lib/ruby_smb/dcerpc/samr.rb).
      # @return [RubySMB::Dcerpc::Samr::SamprHandle] handle to the server object.
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #  SamrConnectResponse packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #  is not STATUS_SUCCESS
      def samr_connect(server_name: '', access: MAXIMUM_ALLOWED)
        samr_connect_request = SamrConnectRequest.new(
          server_name: server_name,
          desired_access: access
        )
        response = dcerpc_request(samr_connect_request)
        begin
          samr_connect_response = SamrConnectResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading SamrConnectResponse'
        end
        unless samr_connect_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::SamrError,
            "Error returned with samr_connect: "\
            "#{WindowsError::NTStatus.find_by_retval(samr_connect_response.error_status.value).join(',')}"
        end
        samr_connect_response.server_handle
      end

      # Obtains the SID of a domain object
      #
      # @param server_handle [RubySMB::Dcerpc::Samr::SamprHandle] RPC context
      #  handle representing the server object
      # @param name [String] The domain name
      # @return [RubySMB::Dcerpc::RpcSid] SID value of a domain that
      #  corresponds to the Name passed in
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #  SamrLookupDomainInSamServerResponse packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #  is not STATUS_SUCCESS
      def samr_lookup_domain(server_handle:, name:)
        samr_lookup_domain_in_sam_server_request = SamrLookupDomainInSamServerRequest.new(
          server_handle: server_handle,
          name: name
        )
        response = dcerpc_request(samr_lookup_domain_in_sam_server_request)
        begin
          samr_lookup_domain_in_sam_server_response = SamrLookupDomainInSamServerResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading SamrLookupDomainInSamServerResponse'
        end
        unless samr_lookup_domain_in_sam_server_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::SamrError,
            "Error returned during domain lookup in SAM server: "\
            "#{WindowsError::NTStatus.find_by_retval(samr_lookup_domain_in_sam_server_response.error_status.value).join(',')}"
        end
        samr_lookup_domain_in_sam_server_response.domain_id
      end

      # Returns a handle to a domain object.
      #
      # @param server_handle [RubySMB::Dcerpc::Samr::SamprHandle] RPC context
      #  handle representing the server object
      # @param access [Numeric] access requested for ServerHandle upon output:
      #  bitwise OR of common and server ACCESS_MASK values (defined in
      #  lib/ruby_smb/dcerpc/samr.rb).
      # @param domain_id [RubySMB::Dcerpc::RpcSid] SID value of a domain
      # @return [RubySMB::Dcerpc::Samr::SamprHandle] handle to the domain object.
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #  SamrOpenDomainResponse packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #  is not STATUS_SUCCESS
      def samr_open_domain(server_handle:, access: MAXIMUM_ALLOWED, domain_id:)
        samr_open_domain_request = SamrOpenDomainRequest.new(
          server_handle: server_handle,
          desired_access: access,
          domain_id: domain_id
        )
        response = dcerpc_request(samr_open_domain_request)
        begin
          samr_open_domain_response = SamrOpenDomainResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading SamrLookupDomainInSamServerResponse'
        end
        unless samr_open_domain_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::SamrError,
            "Error returned during domain lookup in SAM server: "\
            "#{WindowsError::NTStatus.find_by_retval(samr_open_domain_response.error_status.value).join(',')}"
        end
        samr_open_domain_response.domain_handle
      end

      # Enumerates all users in the specified domain.
      #
      # @param domain_handle [RubySMB::Dcerpc::Samr::SamprHandle] RPC context
      #  handle representing the domain object
      # @return [Hash] hash mapping RID and username
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #  SamrEnumerateUsersInDomainResponse packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #  is not STATUS_SUCCESS
      def samr_enumerate_users_in_domain(domain_handle:)
        samr_enum_users_request = SamrEnumerateUsersInDomainRequest.new(
          domain_handle: domain_handle,
          prefered_maximum_length: 65535
        )
        response = dcerpc_request(samr_enum_users_request)
        begin
          samr_enum_users_reponse= SamrEnumerateUsersInDomainResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading SamrEnumerateUsersInDomainResponse'
        end
        unless samr_enum_users_reponse.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::SamrError,
            "Error returned during users enumeration in SAM server: "\
            "#{WindowsError::NTStatus.find_by_retval(samr_enum_users_reponse.error_status.value).join(',')}"
        end
        samr_enum_users_reponse.buffer.buffer.each_with_object({}) do |entry, hash|
          hash[entry.relative_id] = entry.name.buffer
        end
      end

      # Returns the SID of an account, given a RID.
      #
      # @param rid [Numeric] the RID
      # @return [String] The SID of the account referenced by RID
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #  SamrRidToSidResponse packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #  is not STATUS_SUCCESS
      def samr_rid_to_sid(object_handle:, rid:)
        samr_rid_to_sid_request = SamrRidToSidRequest.new(
          object_handle: object_handle,
          rid: rid
        )
        response = dcerpc_request(samr_rid_to_sid_request)
        begin
          samr_rid_to_sid_response = SamrRidToSidResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading SamrRidToSidResponse'
        end
        unless samr_rid_to_sid_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::SamrError,
            "Error returned during SID lookup in SAM server: "\
            "#{WindowsError::NTStatus.find_by_retval(samr_rid_to_sid_response.error_status.value).join(',')}"
        end
        samr_rid_to_sid_response.sid
      end
    end
  end
end

