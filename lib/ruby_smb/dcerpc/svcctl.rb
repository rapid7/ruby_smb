module RubySMB
  module Dcerpc
    module Svcctl

      UUID = '367abb81-9844-35f1-ad32-98f038001003'
      VER_MAJOR = 2
      VER_MINOR = 0

      # Operation numbers
      CLOSE_SERVICE_HANDLE    = 0x0000
      CONTROL_SERVICE         = 0x0001
      QUERY_SERVICE_STATUS    = 0x0006
      CHANGE_SERVICE_CONFIG_W = 0x000B
      OPEN_SC_MANAGER_W       = 0x000F
      OPEN_SERVICE_W          = 0x0010
      QUERY_SERVICE_CONFIG_W  = 0x0011
      START_SERVICE_W         = 0x0013


      class ScRpcHandle < Ndr::NdrContextHandle; end


      #################################
      #           Constants           #
      #################################


      ################
      # Service Access
      # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282

      # In addition to all access rights in this table, SERVICE_ALL_ACCESS
      # includes Delete (DE), Read Control (RC), Write DACL (WD), and Write
      # Owner (WO) access, as specified in ACCESS_MASK (section 2.4.3) of
      # [MS-DTYP].
      SERVICE_ALL_ACCESS            = 0x000F01FF
      # Required to change the configuration of a service.
      SERVICE_CHANGE_CONFIG         = 0x00000002
      # Required to enumerate the services installed on the server.
      SERVICE_ENUMERATE_DEPENDENTS  = 0x00000008
      # Required to request immediate status from the service.
      SERVICE_INTERROGATE           = 0x00000080
      # Required to pause or continue the service.
      SERVICE_PAUSE_CONTINUE        = 0x00000040
      # Required to query the service configuration.
      SERVICE_QUERY_CONFIG          = 0x00000001
      # Required to request the service status.
      SERVICE_QUERY_STATUS          = 0x00000004
      # Required to start the service.
      SERVICE_START                 = 0x00000010
      # Required to stop the service.
      SERVICE_STOP                  = 0x00000020
      # Required to specify a user-defined control code.
      SERVICE_USER_DEFINED_CONTROL  = 0x00000100
      # Required for a service to set its status.
      SERVICE_SET_STATUS            = 0x00008000

      # Specific access types for Service Control Manager object:

      # Required to lock the SCM database.
      SC_MANAGER_LOCK               = 0x00000008
      # Required for a service to be created.
      SC_MANAGER_CREATE_SERVICE     = 0x00000002
      # Required to enumerate a service.
      SC_MANAGER_ENUMERATE_SERVICE  = 0x00000004
      # Required to connect to the SCM.
      SC_MANAGER_CONNECT            = 0x00000001
      # Required to query the lock status of the SCM database.
      SC_MANAGER_QUERY_LOCK_STATUS  = 0x00000010
      # Required to call the RNotifyBootConfigStatus method.
      SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00000020


      ##############
      # Service Type

      # A driver service. These are services that manage devices on the system.
      SERVICE_KERNEL_DRIVER       = 0x00000001
      # A file system driver service. These are services that manage file
      # systems on the system.
      SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
      # A service that runs in its own process.
      SERVICE_WIN32_OWN_PROCESS   = 0x00000010
      # A service that shares a process with other services.
      SERVICE_WIN32_SHARE_PROCESS = 0x00000020

      # The service can interact with the desktop. Only
      # SERVICE_WIN32_OWN_PROCESS and SERVICE_INTERACTIVE_PROCESS OR
      # SERVICE_WIN32_SHARE_PROCESS and SERVICE_INTERACTIVE_PROCESS can be
      # combined.
      SERVICE_INTERACTIVE_PROCESS = 0x00000100

      ####################
      # Service Start Type

      # Starts the driver service when the system boots up. This value is valid
      # only for driver services.
      SERVICE_BOOT_START   = 0x00000000
      # Starts the driver service when the system boots up. This value is valid
      # only for driver services. The services marked SERVICE_SYSTEM_START are
      # started after all SERVICE_BOOT_START services have been started.
      SERVICE_SYSTEM_START = 0x00000001
      # A service started automatically by the SCM during system startup.
      SERVICE_AUTO_START   = 0x00000002
      # Starts the service when a client requests the SCM to start the service.
      SERVICE_DEMAND_START = 0x00000003
      # A service that cannot be started. Attempts to start the service result
      # in the error code ERROR_SERVICE_DISABLED.
      SERVICE_DISABLED     = 0x00000004


      #######################
      # Service Error Control

      # The severity of the error if this service fails to start during startup
      # and the action the SCM takes if failure occurs.

      # The SCM ignores the error and continues the startup operation.
      SERVICE_ERROR_IGNORE   = 0x00000000
      # The SCM logs the error in the event log and continues the startup
      # operation.
      SERVICE_ERROR_NORMAL   = 0x00000001
      # The SCM logs the error in the event log. If the last-known good
      # configuration is being started, the startup operation continues.
      # Otherwise, the system is restarted with the last-known good
      # configuration.
      SERVICE_ERROR_SEVERE   = 0x00000002
      # The SCM SHOULD log the error in the event log if possible. If the
      # last-known good configuration is being started, the startup operation
      # fails. Otherwise, the system is restarted with the last-known good
      # configuration.
      SERVICE_ERROR_CRITICAL = 0x00000003


      #########################################
      # Change Service Config specific constant

      # Service type, start or error control does not change.
      SERVICE_NO_CHANGE        = 0xFFFFFFFF


      ################
      # Current State

      SERVICE_PAUSED           = 0x00000007
      SERVICE_PAUSE_PENDING    = 0x00000006
      SERVICE_CONTINUE_PENDING = 0x00000005
      SERVICE_RUNNING          = 0x00000004
      SERVICE_STOP_PENDING     = 0x00000003
      SERVICE_START_PENDING    = 0x00000002
      SERVICE_STOPPED          = 0x00000001

      ###################
      # Controls Accepted

      # The control codes that the service accepts and processes in its handler
      # function. One or more of the following values can be set. By default,
      # all services accept the SERVICE_CONTROL_INTERROGATE value. A value of
      # zero indicates that no controls are accepted.

      # Service can reread its startup parameters without being stopped and
      # restarted. This control code allows the service to receive
      # SERVICE_CONTROL_PARAMCHANGE notifications.
      SERVICE_ACCEPT_PARAMCHANGE           = 0x00000008
      # Service can be paused and continued. This control code allows the
      # service to receive SERVICE_CONTROL_PAUSE and SERVICE_CONTROL_CONTINUE
      # notifications.
      SERVICE_ACCEPT_PAUSE_CONTINUE        = 0x00000002
      # Service is notified when system shutdown occurs. This control code
      # enables the service to receive SERVICE_CONTROL_SHUTDOWN notifications
      # from the server.
      SERVICE_ACCEPT_SHUTDOWN              = 0x00000004
      # Service can be stopped. This control code allows the service to receive
      # SERVICE_CONTROL_STOP notifications.
      SERVICE_ACCEPT_STOP                  = 0x00000001
      # Service is notified when the computer's hardware profile changes.
      SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020
      # Service is notified when the computer's power status changes.
      SERVICE_ACCEPT_POWEREVENT            = 0x00000040
      # Service is notified when the computer's session status changes.
      SERVICE_ACCEPT_SESSIONCHANGE         = 0x00000080
      # The service can perform preshutdown tasks. SERVICE_ACCEPT_PRESHUTDOWN
      # is sent before sending SERVICE_CONTROL_SHUTDOWN to give more time to
      # services that need extra time before shutdown occurs.
      SERVICE_ACCEPT_PRESHUTDOWN           = 0x00000100
      # Service is notified when the system time changes.
      SERVICE_ACCEPT_TIMECHANGE            = 0x00000200
      # Service is notified when an event for which the service has registered
      # occurs.
      SERVICE_ACCEPT_TRIGGEREVENT          = 0x00000400

      ###################
      # Controls

      # Notifies a paused service that it SHOULD resume. The
      # SERVICE_PAUSE_CONTINUE access right MUST have been granted to the caller
      # when the RPC control handle to the service record was created. The
      # service record MUST have the SERVICE_ACCEPT_PAUSE_CONTINUE bit set in
      # the ServiceStatus.dwControlsAccepted field of the service record.
      SERVICE_CONTROL_CONTINUE       = 0x00000003
      # Notifies a service that it SHOULD report its current status information
      # to the SCM. The SERVICE_INTERROGATE access right MUST have been granted
      # to the caller when the RPC control handle to the service record was
      # created.
      SERVICE_CONTROL_INTERROGATE    = 0x00000004
      # Notifies a service that there is a new component for binding. The
      # SERVICE_PAUSE_CONTINUE access right MUST have been granted to the
      # caller when the RPC control handle to the service record was created.
      # The service record MUST have the SERVICE_ACCEPT_NETBINDCHANGE bit set
      # in the ServiceStatus.dwControlsAccepted field of the service record.
      SERVICE_CONTROL_NETBINDADD     = 0x00000007
      # Notifies a network service that one of its bindings has been disabled.
      # The SERVICE_PAUSE_CONTINUE access right MUST have been granted to the
      # caller when the RPC control handle to the service record was created.
      # The service record MUST have the SERVICE_ACCEPT_NETBINDCHANGE bit set
      # in the ServiceStatus.dwControlsAccepted field of the service record.
      SERVICE_CONTROL_NETBINDDISABLE = 0x0000000A
      # Notifies a network service that a disabled binding has been enabled.
      # The SERVICE_PAUSE_CONTINUE access right MUST have been granted to the
      # caller when the RPC control handle to the service record was created.
      # The service record MUST have the SERVICE_ACCEPT_NETBINDCHANGE bit set
      # in the ServiceStatus.dwControlsAccepted field of the service record.
      SERVICE_CONTROL_NETBINDENABLE  = 0x00000009
      # Notifies a network service that a component for binding has been
      # removed. The SERVICE_PAUSE_CONTINUE access right MUST have been granted
      # to the caller when the RPC control handle to the service record was
      # created. The service record MUST have the SERVICE_ACCEPT_NETBINDCHANGE
      # bit set in the ServiceStatus.dwControlsAccepted field of the service
      # record.
      SERVICE_CONTROL_NETBINDREMOVE  = 0x00000008
      # Notifies a service that its startup parameters have changed. The
      # SERVICE_PAUSE_CONTINUE access right MUST have been granted to the
      # caller when the RPC control handle to the service record was created.
      # The service record MUST have the SERVICE_ACCEPT_PARAMCHANGE bit set in
      # the ServiceStatus.dwControlsAccepted field of the service record.
      SERVICE_CONTROL_PARAMCHANGE    = 0x00000006
      # Notifies a service that it SHOULD pause. The SERVICE_PAUSE_CONTINUE
      # access right MUST have been granted to the caller when the RPC control
      # handle to the service record was created. The service record MUST have
      # the SERVICE_ACCEPT_PAUSE_CONTINUE bit set in the
      # ServiceStatus.dwControlsAccepted field of the service record.
      SERVICE_CONTROL_PAUSE          = 0x00000002
      # Notifies a service that it SHOULD stop. The SERVICE_STOP access right
      # MUST have been granted to the caller when the RPC control handle to the
      # service record was created. The service record MUST have the
      # SERVICE_ACCEPT_STOP bit set in the ServiceStatus.dwControlsAccepted
      # field of the service record.
      SERVICE_CONTROL_STOP           = 0x00000001

      require 'ruby_smb/dcerpc/svcctl/service_status'
      require 'ruby_smb/dcerpc/svcctl/open_sc_manager_w_request'
      require 'ruby_smb/dcerpc/svcctl/open_sc_manager_w_response'
      require 'ruby_smb/dcerpc/svcctl/open_service_w_request'
      require 'ruby_smb/dcerpc/svcctl/open_service_w_response'
      require 'ruby_smb/dcerpc/svcctl/query_service_status_request'
      require 'ruby_smb/dcerpc/svcctl/query_service_status_response'
      require 'ruby_smb/dcerpc/svcctl/query_service_config_w_request'
      require 'ruby_smb/dcerpc/svcctl/query_service_config_w_response'
      require 'ruby_smb/dcerpc/svcctl/change_service_config_w_request'
      require 'ruby_smb/dcerpc/svcctl/change_service_config_w_response'
      require 'ruby_smb/dcerpc/svcctl/start_service_w_request'
      require 'ruby_smb/dcerpc/svcctl/start_service_w_response'
      require 'ruby_smb/dcerpc/svcctl/control_service_request'
      require 'ruby_smb/dcerpc/svcctl/control_service_response'
      require 'ruby_smb/dcerpc/svcctl/close_service_handle_request'
      require 'ruby_smb/dcerpc/svcctl/close_service_handle_response'

      # Open the SCM database on the specified server.
      #
      # @param rhost [String] the server's machine name
      # @return [RubySMB::Dcerpc::Svcctl::ScRpcHandle] handle to the newly opened SCM database
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a OpenSCManagerWResponse packet
      # @raise [RubySMB::Dcerpc::Error::SvcctlError] if the response error status is not ERROR_SUCCESS
      def open_sc_manager_w(rhost, access = SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SC_MANAGER_ENUMERATE_SERVICE)
        open_sc_manager_w_request = OpenSCManagerWRequest.new(dw_desired_access: access)
        open_sc_manager_w_request.lp_machine_name = rhost
        open_sc_manager_w_request.lp_database_name = 'ServicesActive'
        response = dcerpc_request(open_sc_manager_w_request)
        begin
          open_sc_manager_w_response = OpenSCManagerWResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading OpenSCManagerWResponse'
        end
        unless open_sc_manager_w_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::SvcctlError,
            "Error returned when opening Service Control Manager (SCM): "\
            "#{WindowsError::Win32.find_by_retval(open_sc_manager_w_response.error_status.value).join(',')}"
        end
        open_sc_manager_w_response.lp_sc_handle
      end

      # Creates an RPC context handle to an existing service record.
      #
      # @param scm_handle [RubySMB::Dcerpc::Svcctl::ScRpcHandle] handle to the SCM database
      # @param service_name [Srting] the ServiceName of the service record
      # @param access [Integer] access right
      # @return [RubySMB::Dcerpc::Svcctl::ScRpcHandle] handle to the found service record
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a OpenServiceWResponse packet
      # @raise [RubySMB::Dcerpc::Error::SvcctlError] if the response error status is not ERROR_SUCCESS
      def open_service_w(scm_handle, service_name, access = SERVICE_ALL_ACCESS)
        open_service_w_request = OpenServiceWRequest.new(dw_desired_access: access)
        open_service_w_request.lp_sc_handle = scm_handle
        open_service_w_request.lp_service_name = service_name
        response = dcerpc_request(open_service_w_request)
        begin
          open_sercice_w_response = OpenServiceWResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading OpenServiceWResponse'
        end
        unless open_sercice_w_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::SvcctlError,
            "Error returned when opening #{service_name} service: "\
            "#{WindowsError::Win32.find_by_retval(open_sercice_w_response.error_status.value).join(',')}"
        end
        open_sercice_w_response.lp_sc_handle
      end

      # Returns the current status of the specified service
      #
      # @param scm_handle [RubySMB::Dcerpc::Svcctl::ScRpcHandle] handle to the service record
      # @return [RubySMB::Dcerpc::Svcctl::ServiceStatus] structure that contains the status information for the service
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a QueryServiceStatusResponse packet
      # @raise [RubySMB::Dcerpc::Error::SvcctlError] if the response error status is not ERROR_SUCCESS
      def query_service_status(svc_handle)
        qss_request = QueryServiceStatusRequest.new
        qss_request.h_service = svc_handle
        response = dcerpc_request(qss_request)
        begin
          qss_response = QueryServiceStatusResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading QueryServiceStatusResponse'
        end
        unless qss_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::SvcctlError,
            "Error returned when querying service status: "\
            "#{WindowsError::Win32.find_by_retval(qss_response.error_status.value).join(',')}"
        end
        qss_response.lp_service_status
      end

      # Returns the configuration parameters of the specified service
      #
      # @param scm_handle [RubySMB::Dcerpc::Svcctl::ScRpcHandle] handle to the service record
      # @return [RubySMB::Dcerpc::Svcctl::QueryServiceConfigW] structure that contains the configuration parameters for the service
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a QueryServiceConfigWResponse packet
      # @raise [RubySMB::Dcerpc::Error::SvcctlError] if the response error status is not ERROR_SUCCESS
      def query_service_config(svc_handle)
        qsc_request = QueryServiceConfigWRequest.new
        qsc_request.h_service = svc_handle
        qsc_request.cb_buf_size = 0
        response = dcerpc_request(qsc_request)
        begin
          qsc_response = QueryServiceConfigWResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading QueryServiceConfigWResponse'
        end
        if qsc_response.error_status == WindowsError::Win32::ERROR_INSUFFICIENT_BUFFER
          qsc_request.cb_buf_size = qsc_response.pcb_bytes_needed
          response = dcerpc_request(qsc_request)
          begin
            qsc_response = QueryServiceConfigWResponse.read(response)
          rescue IOError
            raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading QueryServiceConfigWResponse'
          end
        end
        unless qsc_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::SvcctlError,
            "Error returned when querying service configuration: "\
            "#{WindowsError::Win32.find_by_retval(qsc_response.error_status.value).join(',')}"
        end
        qsc_response.lp_service_config
      end

      # Changes a service's configuration parameters in the SCM database
      #
      # @param scm_handle [RubySMB::Dcerpc::Svcctl::ScRpcHandle] handle to the service record
      # @param opts [Hash] configuration parameters to change
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a ChangeServiceConfigWResponse packet
      # @raise [RubySMB::Dcerpc::Error::SvcctlError] if the response error status is not ERROR_SUCCESS
      def change_service_config_w(svc_handle, opts = {})
        opts = {
          h_service:             svc_handle,
          dw_service_type:       opts[:service_type] || SERVICE_NO_CHANGE,
          dw_start_type:         opts[:start_type] || SERVICE_NO_CHANGE,
          dw_error_control:      opts[:error_control] || SERVICE_NO_CHANGE,
          lp_binary_path_name:   opts[:binary_path_name] || :null,
          lp_load_order_group:   opts[:load_order_group] || :null,
          dw_tag_id:             opts[:tag_id] || :null,
          lp_dependencies:       opts[:dependencies] || [],
          lp_service_start_name: opts[:service_start_name] || :null,
          lp_password:           opts[:password] || [],
          lp_display_name:       opts[:display_name] || :null
        }

        csc_request = ChangeServiceConfigWRequest.new(opts)
        response = dcerpc_request(csc_request)
        begin
          csc_response = ChangeServiceConfigWResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading ChangeServiceConfigWResponse'
        end
        unless csc_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::SvcctlError,
            "Error returned when changing the service configuration: "\
            "#{WindowsError::Win32.find_by_retval(csc_response.error_status.value).join(',')}"
        end
      end

      # Starts a specified service
      #
      # @param scm_handle [RubySMB::Dcerpc::Svcctl::ScRpcHandle] handle to the service record
      # @param argv [Array<String>] arguments to the service (Array of
      #   strings). The first element in argv must be the name of the service.
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a StartServiceWResponse packet
      # @raise [RubySMB::Dcerpc::Error::SvcctlError] if the response error status is not ERROR_SUCCESS
      def start_service_w(svc_handle, argv = [])
        ss_request = StartServiceWRequest.new(h_service: svc_handle)
        unless argv.empty?
          ss_request.argc = argv.size
          ss_request.argv = argv
        end
        response = dcerpc_request(ss_request)
        begin
          ss_response = StartServiceWResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading StartServiceWResponse'
        end
        unless ss_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::SvcctlError,
            "Error returned when starting the service: "\
            "#{WindowsError::Win32.find_by_retval(ss_response.error_status.value).join(',')}"
        end
      end

      # Send a control code to a specific service handle
      #
      # @param scm_handle [RubySMB::Dcerpc::Svcctl::ScRpcHandle] handle to the service record
      # @param control [Integer] control code
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a ControlServiceResponse packet
      # @raise [RubySMB::Dcerpc::Error::SvcctlError] if the response error status is not ERROR_SUCCESS
      def control_service(svc_handle, control)
        cs_request = ControlServiceRequest.new(h_service: svc_handle, dw_control: control)
        response = dcerpc_request(cs_request)
        begin
          cs_response = ControlServiceResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading ControlServiceResponse'
        end
        unless cs_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::SvcctlError,
            "Error returned when sending a control to the service: "\
            "#{WindowsError::Win32.find_by_retval(cs_response.error_status.value).join(',')}"
        end
      end

      # Releases the handle to the specified service or the SCM database.
      #
      # @param scm_handle [RubySMB::Dcerpc::Svcctl::ScRpcHandle] handle to the service record or to the SCM database
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a CloseServiceHandleResponse packet
      # @raise [RubySMB::Dcerpc::Error::SvcctlError] if the response error status is not ERROR_SUCCESS
      def close_service_handle(svc_handle)
        csh_request = CloseServiceHandleRequest.new(h_sc_object: svc_handle)
        response = dcerpc_request(csh_request)
        begin
          csh_response = CloseServiceHandleResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading CloseServiceHandleResponse'
        end
        unless csh_response.error_status == WindowsError::Win32::ERROR_SUCCESS
          raise RubySMB::Dcerpc::Error::SvcctlError,
            "Error returned when closing the service: "\
            "#{WindowsError::Win32.find_by_retval(csh_response.error_status.value).join(',')}"
        end
      end
    end
  end
end
