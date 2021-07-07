RSpec.describe RubySMB::Dcerpc::Svcctl do
  let(:svcctl) do
    RubySMB::SMB1::Pipe.new(
      tree: double('Tree'),
      response: RubySMB::SMB1::Packet::NtCreateAndxResponse.new,
      name: 'svcctl'
    )
  end

  describe '#open_sc_manager_w' do
    let(:rhost) { '1.2.3.4' }
    let(:open_sc_manager_w_request) { double('OpenSCManagerW Request Packet') }
    let(:response)               { double('Response') }
    let(:open_sc_manager_w_response) { double('OpenSCManagerW Response Packet') }
    let(:lp_sc_handle) { double('LpScHandle') }
    before :example do
      allow(described_class::OpenSCManagerWRequest).to receive(:new).and_return(open_sc_manager_w_request)
      allow(open_sc_manager_w_request).to receive_messages(
        :lp_machine_name=  => nil,
        :lp_database_name= => nil,
      )
      allow(svcctl).to receive(:dcerpc_request).and_return(response)
      allow(described_class::OpenSCManagerWResponse).to receive(:read).and_return(open_sc_manager_w_response)
      allow(open_sc_manager_w_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :lp_sc_handle => lp_sc_handle
      )
    end

    it 'create the expected OpenSCManagerWRequest packet with the default desired access' do
      access =
        described_class::SERVICE_START |
        described_class::SERVICE_STOP |
        described_class::SERVICE_CHANGE_CONFIG |
        described_class::SERVICE_QUERY_CONFIG |
        described_class::SERVICE_QUERY_STATUS |
        described_class::SERVICE_ENUMERATE_DEPENDENTS |
        described_class::SC_MANAGER_ENUMERATE_SERVICE
      svcctl.open_sc_manager_w(rhost)
      expect(described_class::OpenSCManagerWRequest).to have_received(:new).with(dw_desired_access: access)
    end

    it 'create the expected OpenSCManagerWRequest packet with custom desired access' do
      access =
        described_class::SERVICE_QUERY_CONFIG |
        described_class::SERVICE_ENUMERATE_DEPENDENTS |
        described_class::SC_MANAGER_ENUMERATE_SERVICE
      svcctl.open_sc_manager_w(rhost, access)
      expect(described_class::OpenSCManagerWRequest).to have_received(:new).with(dw_desired_access: access)
    end

    it 'sets the expected fields on the request packet' do
      svcctl.open_sc_manager_w(rhost)
      expect(open_sc_manager_w_request).to have_received(:lp_machine_name=).with(rhost)
      expect(open_sc_manager_w_request).to have_received(:lp_database_name=).with('ServicesActive')
    end

    it 'sends the expected dcerpc request' do
      svcctl.open_sc_manager_w(rhost)
      expect(svcctl).to have_received(:dcerpc_request).with(open_sc_manager_w_request)
    end

    it 'creates a OpenSCManagerWResponse structure from the expected dcerpc response' do
      svcctl.open_sc_manager_w(rhost)
      expect(described_class::OpenSCManagerWResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::OpenSCManagerWResponse).to receive(:read).and_raise(IOError)
        expect { svcctl.open_sc_manager_w(rhost) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(open_sc_manager_w_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { svcctl.open_sc_manager_w(rhost) }.to raise_error(RubySMB::Dcerpc::Error::SvcctlError)
      end
    end

    it 'returns the expected handler' do
      expect(svcctl.open_sc_manager_w(rhost)).to eq(lp_sc_handle)
    end
  end

  describe '#open_service_w' do
    let(:scm_handle) { '1.2.3.4' }
    let(:service_name) { 'MyService' }
    let(:open_service_w_request) { double('OpenServiceW Request Packet') }
    let(:response)               { double('Response') }
    let(:open_service_w_response) { double('OpenServiceW Response Packet') }
    let(:lp_sc_handle) { double('LpScHandle') }
    before :example do
      allow(described_class::OpenServiceWRequest).to receive(:new).and_return(open_service_w_request)
      allow(open_service_w_request).to receive_messages(
        :lp_sc_handle=  => nil,
        :lp_service_name= => nil,
      )
      allow(svcctl).to receive(:dcerpc_request).and_return(response)
      allow(described_class::OpenServiceWResponse).to receive(:read).and_return(open_service_w_response)
      allow(open_service_w_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :lp_sc_handle => lp_sc_handle
      )
    end

    it 'create the expected OpenServiceWRequest packet with the default desired access' do
      access = described_class::SERVICE_ALL_ACCESS
      svcctl.open_service_w(scm_handle, service_name)
      expect(described_class::OpenServiceWRequest).to have_received(:new).with(dw_desired_access: access)
    end

    it 'create the expected OpenServiceWRequest packet with custom desired access' do
      access =
        described_class::SERVICE_QUERY_CONFIG |
        described_class::SERVICE_ENUMERATE_DEPENDENTS |
        described_class::SC_MANAGER_ENUMERATE_SERVICE
      svcctl.open_service_w(scm_handle, service_name, access)
      expect(described_class::OpenServiceWRequest).to have_received(:new).with(dw_desired_access: access)
    end

    it 'sets the expected fields on the request packet' do
      svcctl.open_service_w(scm_handle, service_name)
      expect(open_service_w_request).to have_received(:lp_sc_handle=).with(scm_handle)
      expect(open_service_w_request).to have_received(:lp_service_name=).with(service_name)
    end

    it 'sends the expected dcerpc request' do
      svcctl.open_service_w(scm_handle, service_name)
      expect(svcctl).to have_received(:dcerpc_request).with(open_service_w_request)
    end

    it 'creates a OpenServiceWResponse structure from the expected dcerpc response' do
      svcctl.open_service_w(scm_handle, service_name)
      expect(described_class::OpenServiceWResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::OpenServiceWResponse).to receive(:read).and_raise(IOError)
        expect { svcctl.open_service_w(scm_handle, service_name) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(open_service_w_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { svcctl.open_service_w(scm_handle, service_name) }.to raise_error(RubySMB::Dcerpc::Error::SvcctlError)
      end
    end

    it 'returns the expected handler' do
      expect(svcctl.open_service_w(scm_handle, service_name)).to eq(lp_sc_handle)
    end
  end

  describe '#query_service_status' do
    let(:svc_handle) { double('Service Handle') }
    let(:query_service_status_request) { double('QueryServiceStatus Request Packet') }
    let(:response)               { double('Response') }
    let(:query_service_status_response) { double('QueryServiceStatus Response Packet') }
    let(:lp_service_status) { double('LpServiceStatus') }
    before :example do
      allow(described_class::QueryServiceStatusRequest).to receive(:new).and_return(query_service_status_request)
      allow(query_service_status_request).to receive_messages(
        :h_service=  => nil,
      )
      allow(svcctl).to receive(:dcerpc_request).and_return(response)
      allow(described_class::QueryServiceStatusResponse).to receive(:read).and_return(query_service_status_response)
      allow(query_service_status_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :lp_service_status => lp_service_status
      )
    end

    it 'create the expected QueryServiceStatusRequest packet' do
      svcctl.query_service_status(svc_handle)
      expect(described_class::QueryServiceStatusRequest).to have_received(:new)
    end

    it 'sets the expected fields on the request packet' do
      svcctl.query_service_status(svc_handle)
      expect(query_service_status_request).to have_received(:h_service=).with(svc_handle)
    end

    it 'sends the expected dcerpc request' do
      svcctl.query_service_status(svc_handle)
      expect(svcctl).to have_received(:dcerpc_request).with(query_service_status_request)
    end

    it 'creates a QueryServiceStatusResponse structure from the expected dcerpc response' do
      svcctl.query_service_status(svc_handle)
      expect(described_class::QueryServiceStatusResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::QueryServiceStatusResponse).to receive(:read).and_raise(IOError)
        expect { svcctl.query_service_status(svc_handle) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(query_service_status_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { svcctl.query_service_status(svc_handle) }.to raise_error(RubySMB::Dcerpc::Error::SvcctlError)
      end
    end

    it 'returns the expected handler' do
      expect(svcctl.query_service_status(svc_handle)).to eq(lp_service_status)
    end
  end

  describe '#query_service_config' do
    let(:svc_handle) { double('Service Handle') }
    let(:query_service_config_request) { double('QueryServiceConfigW Request Packet') }
    let(:response)               { double('Response') }
    let(:query_service_config_response) { double('QueryServiceConfigW Response Packet') }
    let(:lp_service_config) { double('LpServiceConfig') }
    before :example do
      allow(described_class::QueryServiceConfigWRequest).to receive(:new).and_return(query_service_config_request)
      allow(query_service_config_request).to receive_messages(
        :h_service=  => nil,
        :cb_buf_size=  => nil,
      )
      allow(svcctl).to receive(:dcerpc_request).and_return(response)
      allow(described_class::QueryServiceConfigWResponse).to receive(:read).and_return(query_service_config_response)
      allow(query_service_config_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :lp_service_config => lp_service_config
      )
    end

    it 'create the expected QueryServiceConfigWRequest packet' do
      svcctl.query_service_config(svc_handle)
      expect(described_class::QueryServiceConfigWRequest).to have_received(:new)
    end

    it 'sets the expected fields on the request packet' do
      svcctl.query_service_config(svc_handle)
      expect(query_service_config_request).to have_received(:h_service=).with(svc_handle)
      expect(query_service_config_request).to have_received(:cb_buf_size=).with(0)
    end

    it 'sends the expected dcerpc request' do
      svcctl.query_service_config(svc_handle)
      expect(svcctl).to have_received(:dcerpc_request).with(query_service_config_request)
    end

    it 'creates a QueryServiceConfigWResponse structure from the expected dcerpc response' do
      svcctl.query_service_config(svc_handle)
      expect(described_class::QueryServiceConfigWResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::QueryServiceConfigWResponse).to receive(:read).and_raise(IOError)
        expect { svcctl.query_service_config(svc_handle) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(query_service_config_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { svcctl.query_service_config(svc_handle) }.to raise_error(RubySMB::Dcerpc::Error::SvcctlError)
      end
    end

    it 'returns the expected handler' do
      expect(svcctl.query_service_config(svc_handle)).to eq(lp_service_config)
    end
  end

  describe '#change_service_config_w' do
    let(:svc_handle) { double('Service Handle') }
    let(:change_service_config_w_request) { double('ChangeServiceConfigW Request Packet') }
    let(:response)               { double('Response') }
    let(:change_service_config_w_response) { double('ChangeServiceConfigW Response Packet') }
    before :example do
      allow(described_class::ChangeServiceConfigWRequest).to receive(:new).and_return(change_service_config_w_request)
      allow(svcctl).to receive(:dcerpc_request).and_return(response)
      allow(described_class::ChangeServiceConfigWResponse).to receive(:read).and_return(change_service_config_w_response)
      allow(change_service_config_w_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
      )
    end

    it 'create the expected ChangeServiceConfigWRequest packet with the default options' do
      opts = {
        h_service:             svc_handle,
        dw_service_type:       described_class::SERVICE_NO_CHANGE,
        dw_start_type:         described_class::SERVICE_NO_CHANGE,
        dw_error_control:      described_class::SERVICE_NO_CHANGE,
        lp_binary_path_name:   :null,
        lp_load_order_group:   :null,
        dw_tag_id:             :null,
        lp_dependencies:       [],
        lp_service_start_name: :null,
        lp_password:           [],
        lp_display_name:       :null
      }
      svcctl.change_service_config_w(svc_handle)
      expect(described_class::ChangeServiceConfigWRequest).to have_received(:new).with(opts)
    end

    it 'create the expected ChangeServiceConfigWRequest packet with custom options' do
      opts = {
        service:            svc_handle,
        service_type:       described_class::SERVICE_KERNEL_DRIVER,
        start_type:         described_class::SERVICE_SYSTEM_START,
        error_control:      described_class::SERVICE_ERROR_SEVERE,
        binary_path_name:   '\\path\\to\\binary',
        load_order_group:   'load order',
        tag_id:              2,
        dependencies:       [1, 2, 3],
        service_start_name: 'My service',
        password:           [1, 2, 3],
        display_name:       'Name'
      }
      opts2 = {
        h_service:             svc_handle,
        dw_service_type:       opts[:service_type],
        dw_start_type:         opts[:start_type],
        dw_error_control:      opts[:error_control],
        lp_binary_path_name:   opts[:binary_path_name],
        lp_load_order_group:   opts[:load_order_group],
        dw_tag_id:             opts[:tag_id],
        lp_dependencies:       opts[:dependencies],
        lp_service_start_name: opts[:service_start_name],
        lp_password:           opts[:password],
        lp_display_name:       opts[:display_name]
      }
      svcctl.change_service_config_w(svc_handle, opts)
      expect(described_class::ChangeServiceConfigWRequest).to have_received(:new).with(opts2)
    end

    it 'sends the expected dcerpc request' do
      svcctl.change_service_config_w(svc_handle)
      expect(svcctl).to have_received(:dcerpc_request).with(change_service_config_w_request)
    end

    it 'creates a ChangeServiceConfigWResponse structure from the expected dcerpc response' do
      svcctl.change_service_config_w(svc_handle)
      expect(described_class::ChangeServiceConfigWResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::ChangeServiceConfigWResponse).to receive(:read).and_raise(IOError)
        expect { svcctl.change_service_config_w(svc_handle) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(change_service_config_w_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { svcctl.change_service_config_w(svc_handle) }.to raise_error(RubySMB::Dcerpc::Error::SvcctlError)
      end
    end
  end

  describe '#start_service_w' do
    let(:svc_handle) { double('Service Handle') }
    let(:start_service_w_request) { double('StartServiceW Request Packet') }
    let(:response)               { double('Response') }
    let(:start_service_w_response) { double('StartServiceW Response Packet') }
    before :example do
      allow(described_class::StartServiceWRequest).to receive(:new).and_return(start_service_w_request)
      allow(start_service_w_request).to receive_messages(
        :h_service=  => nil,
        :argc=  => nil,
        :argv=  => nil,
      )
      allow(svcctl).to receive(:dcerpc_request).and_return(response)
      allow(described_class::StartServiceWResponse).to receive(:read).and_return(start_service_w_response)
      allow(start_service_w_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
      )
    end

    it 'create the expected StartServiceWRequest packet' do
      svcctl.start_service_w(svc_handle)
      expect(described_class::StartServiceWRequest).to have_received(:new)
    end

    it 'sets the provided Service start arguments' do
      argv = ['my', 'arguments', 'to', 'test']
      svcctl.start_service_w(svc_handle, argv)
      expect(start_service_w_request).to have_received(:argc=).with(argv.size)
      expect(start_service_w_request).to have_received(:argv=).with(argv)
    end

    it 'sends the expected dcerpc request' do
      svcctl.start_service_w(svc_handle)
      expect(svcctl).to have_received(:dcerpc_request).with(start_service_w_request)
    end

    it 'creates a StartServiceWResponse structure from the expected dcerpc response' do
      svcctl.start_service_w(svc_handle)
      expect(described_class::StartServiceWResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::StartServiceWResponse).to receive(:read).and_raise(IOError)
        expect { svcctl.start_service_w(svc_handle) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(start_service_w_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { svcctl.start_service_w(svc_handle) }.to raise_error(RubySMB::Dcerpc::Error::SvcctlError)
      end
    end
  end

  describe '#control_service' do
    let(:svc_handle) { double('Service Handle') }
    let(:control) { double('Control') }
    let(:control_service_request) { double('ControlService Request Packet') }
    let(:response)               { double('Response') }
    let(:control_service_response) { double('ControlService Response Packet') }
    before :example do
      allow(described_class::ControlServiceRequest).to receive(:new).and_return(control_service_request)
      allow(svcctl).to receive(:dcerpc_request).and_return(response)
      allow(described_class::ControlServiceResponse).to receive(:read).and_return(control_service_response)
      allow(control_service_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
      )
    end

    it 'create the expected ControlServiceRequest packet' do
      svcctl.control_service(svc_handle, control)
      expect(described_class::ControlServiceRequest).to have_received(:new).with(h_service: svc_handle, dw_control: control)
    end

    it 'sends the expected dcerpc request' do
      svcctl.control_service(svc_handle, control)
      expect(svcctl).to have_received(:dcerpc_request).with(control_service_request)
    end

    it 'creates a ControlServiceResponse structure from the expected dcerpc response' do
      svcctl.control_service(svc_handle, control)
      expect(described_class::ControlServiceResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::ControlServiceResponse).to receive(:read).and_raise(IOError)
        expect { svcctl.control_service(svc_handle, control) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(control_service_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { svcctl.control_service(svc_handle, control) }.to raise_error(RubySMB::Dcerpc::Error::SvcctlError)
      end
    end
  end

  describe '#close_service_handle' do
    let(:svc_handle) { double('Service Handle') }
    let(:close_service_handle_request) { double('CloseServiceHandle Request Packet') }
    let(:response)               { double('Response') }
    let(:close_service_handle_response) { double('CloseServiceHandle Response Packet') }
    before :example do
      allow(described_class::CloseServiceHandleRequest).to receive(:new).and_return(close_service_handle_request)
      allow(svcctl).to receive(:dcerpc_request).and_return(response)
      allow(described_class::CloseServiceHandleResponse).to receive(:read).and_return(close_service_handle_response)
      allow(close_service_handle_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
      )
    end

    it 'create the expected CloseServiceHandleRequest packet' do
      svcctl.close_service_handle(svc_handle)
      expect(described_class::CloseServiceHandleRequest).to have_received(:new).with(h_sc_object: svc_handle)
    end

    it 'sends the expected dcerpc request' do
      svcctl.close_service_handle(svc_handle)
      expect(svcctl).to have_received(:dcerpc_request).with(close_service_handle_request)
    end

    it 'creates a CloseServiceHandleResponse structure from the expected dcerpc response' do
      svcctl.close_service_handle(svc_handle)
      expect(described_class::CloseServiceHandleResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::CloseServiceHandleResponse).to receive(:read).and_raise(IOError)
        expect { svcctl.close_service_handle(svc_handle) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(close_service_handle_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { svcctl.close_service_handle(svc_handle) }.to raise_error(RubySMB::Dcerpc::Error::SvcctlError)
      end
    end
  end
end
