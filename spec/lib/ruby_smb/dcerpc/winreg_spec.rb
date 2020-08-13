RSpec.describe RubySMB::Dcerpc::Winreg do
  let(:winreg) do
    RubySMB::SMB1::Pipe.new(
      tree: double('Tree'),
      response: RubySMB::SMB1::Packet::NtCreateAndxResponse.new,
      name: 'winreg'
    )
  end

  describe '#open_root_key' do
    let(:root_key_request_packet)  { double('Root Key Request Packet') }
    let(:response)                 { double('Response') }
    let(:root_key_response_packet) { double('Root Key Response Packet') }
    let(:ph_key)                   { double('PHKEY') }
    before :example do
      allow(described_class::OpenRootKeyRequest).to receive(:new).and_return(root_key_request_packet)
      allow(winreg).to receive(:dcerpc_request).and_return(response)
      allow(described_class::OpenRootKeyResponse).to receive(:read).and_return(root_key_response_packet)
      allow(root_key_response_packet).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :ph_key       => ph_key
      )
    end

    context 'when the root key is unknown' do
      it 'raises an ArgumentError exception' do
        expect { winreg.open_root_key('UNKNOWN') }.to raise_error(ArgumentError)
      end
    end

    it 'create the expected OpenRootKeyRequest packet' do
      winreg.open_root_key('HKLM')
      expect(described_class::OpenRootKeyRequest).to have_received(:new).with(opnum: described_class::OPEN_HKLM)
    end

    it 'sends the expected dcerpc request' do
      winreg.open_root_key('HKLM')
      expect(winreg).to have_received(:dcerpc_request).with(root_key_request_packet)
    end

    it 'creates a OpenRootKeyResponse structure from the expected dcerpc response' do
      winreg.open_root_key('HKLM')
      expect(described_class::OpenRootKeyResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::OpenRootKeyResponse).to receive(:read).and_raise(IOError)
        expect { winreg.open_root_key('HKLM') }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(root_key_response_packet).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { winreg.open_root_key('HKLM') }.to raise_error(RubySMB::Dcerpc::Error::WinregError)
      end
    end

    it 'returns the expected handler' do
      expect(winreg.open_root_key('HKLM')).to eq(ph_key)
    end
  end

  describe '#open_key' do
    let(:handle)                 { double('Handle') }
    let(:sub_key)                { double('Sub-key') }
    let(:openkey_request_packet) { double('OpenKey Request Packet') }
    let(:regsam)                 { double('Regsam') }
    let(:response)               { double('Response') }
    let(:open_key_response)      { double('OpenKey Response') }
    let(:phk_result)             { double('Phk Result') }
    before :example do
      allow(described_class::OpenKeyRequest).to receive(:new).and_return(openkey_request_packet)
      allow(openkey_request_packet).to receive(:sam_desired).and_return(regsam)
      allow(regsam).to receive_messages(
        :read_control=           => nil,
        :key_query_value=        => nil,
        :key_enumerate_sub_keys= => nil,
        :key_notify=             => nil,
      )
      allow(winreg).to receive(:dcerpc_request).and_return(response)
      allow(described_class::OpenKeyResponse).to receive(:read).and_return(open_key_response)
      allow(open_key_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :phk_result   => phk_result
      )
    end

    it 'create the expected OpenKeyRequest packet' do
      winreg.open_key(handle, sub_key)
      expect(described_class::OpenKeyRequest).to have_received(:new).with(hkey: handle, lp_sub_key: sub_key)
    end

    it 'sets the expected user rights on the request packet' do
      winreg.open_key(handle, sub_key)
      expect(regsam).to have_received(:read_control=).with(1)
      expect(regsam).to have_received(:key_query_value=).with(1)
      expect(regsam).to have_received(:key_enumerate_sub_keys=).with(1)
      expect(regsam).to have_received(:key_notify=).with(1)
    end

    it 'sends the expected dcerpc request' do
      winreg.open_key(handle, sub_key)
      expect(winreg).to have_received(:dcerpc_request).with(openkey_request_packet)
    end

    it 'creates a OpenKeyResponse structure from the expected dcerpc response' do
      winreg.open_key(handle, sub_key)
      expect(described_class::OpenKeyResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::OpenKeyResponse).to receive(:read).and_raise(IOError)
        expect { winreg.open_key(handle, sub_key) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(open_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { winreg.open_key(handle, sub_key) }.to raise_error(RubySMB::Dcerpc::Error::WinregError)
      end
    end

    it 'returns the expected handler' do
      expect(winreg.open_key(handle, sub_key)).to eq(phk_result)
    end
  end

  describe '#query_value' do
    let(:handle)                      { double('Handle') }
    let(:value_name)                  { double('Value Name') }
    let(:query_value_request_packet) { double('Query Value Request Packet #1') }
    let(:lp_data1)                    { double('LpData #1') }
    let(:lp_data2)                    { double('LpData #2') }
    let(:response1)                   { double('Response #1') }
    let(:response2)                   { double('Response #2') }
    let(:query_value_response1)       { double('Query Value Response #1') }
    let(:query_value_response2)       { double('Query Value Response #2') }
    let(:data)                        { double('Data') }
    let(:lpcb_data)                   { double('LpcbData') }
    let(:lpcb_data_referent)          { double('LpcbData Referent') }
    let(:lp_data2_referent)           { double('LpData Referent') }
    before :example do
      allow(described_class::QueryValueRequest).to receive(:new).and_return(query_value_request_packet)
      allow(query_value_request_packet).to receive_messages(
        :lp_type=   => nil,
        :lpcb_data= => nil,
        :lpcb_len=  => nil,
        :lp_data=   => nil,
        :lp_data    => lp_data2,
      )
      allow(lp_data2).to receive(:referent).and_return(lp_data2_referent)
      allow(lp_data2_referent).to receive(:max_count=)
      first_request = true
      allow(winreg).to receive(:dcerpc_request) do |arg|
        if first_request
          first_request = false
          response1
        else
          response2
        end
      end
      allow(described_class::QueryValueResponse).to receive(:read).with(response1).and_return(query_value_response1)
      allow(described_class::QueryValueResponse).to receive(:read).with(response2).and_return(query_value_response2)
      allow(query_value_response1).to receive(:error_status).and_return(WindowsError::Win32::ERROR_SUCCESS)
      allow(query_value_response2).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :data         => data
      )
      allow(query_value_response1).to receive(:lpcb_data).and_return(lpcb_data)
      allow(lpcb_data).to receive(:referent).and_return(lpcb_data_referent)
    end

    it 'create the expected QueryValueRequest packets' do
      winreg.query_value(handle, value_name)
      expect(described_class::QueryValueRequest).to have_received(:new).with(hkey: handle, lp_value_name: value_name)
    end

    it 'sets the expected fields on the request packet' do
      winreg.query_value(handle, value_name)
      expect(query_value_request_packet).to have_received(:lp_type=).with(0)
      expect(query_value_request_packet).to have_received(:lpcb_data=).with(0)
      expect(query_value_request_packet).to have_received(:lpcb_len=).with(0)
      expect(query_value_request_packet).to have_received(:lpcb_data=).with(lpcb_data)
      expect(query_value_request_packet).to have_received(:lp_data=).with([])
      expect(lp_data2_referent).to have_received(:max_count=).with(lpcb_data_referent)
    end

    it 'sends the expected dcerpc requests' do
      winreg.query_value(handle, value_name)
      expect(winreg).to have_received(:dcerpc_request).with(query_value_request_packet).twice
    end

    context 'when receiving the first response' do
      it 'creates a QueryValueResponse structure from the expected dcerpc response' do
        winreg.query_value(handle, value_name)
        expect(described_class::QueryValueResponse).to have_received(:read).with(response1)
      end

      context 'when an IOError occurs while parsing the response' do
        it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
          allow(described_class::QueryValueResponse).to receive(:read).with(response1).and_raise(IOError)
          expect { winreg.query_value(handle, value_name) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      context 'when the first response error status is not WindowsError::Win32::ERROR_SUCCESS' do
        it 'raises a RubySMB::Dcerpc::Error::WinregError' do
          allow(query_value_response1).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
          expect { winreg.query_value(handle, value_name) }.to raise_error(RubySMB::Dcerpc::Error::WinregError)
        end
      end
    end

    context 'when receiving the second response' do
      it 'creates a QueryValueResponse structure from the expected dcerpc response' do
        winreg.query_value(handle, value_name)
        expect(described_class::QueryValueResponse).to have_received(:read).with(response2)
      end

      context 'when an IOError occurs while parsing the response' do
        it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
          allow(described_class::QueryValueResponse).to receive(:read).with(response2).and_raise(IOError)
          expect { winreg.query_value(handle, value_name) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
        end
      end

      context 'when the first response error status is not WindowsError::Win32::ERROR_SUCCESS' do
        it 'raises a RubySMB::Dcerpc::Error::WinregError' do
          allow(query_value_response2).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
          expect { winreg.query_value(handle, value_name) }.to raise_error(RubySMB::Dcerpc::Error::WinregError)
        end
      end
    end

    it 'returns the expected response data' do
      expect(winreg.query_value(handle, value_name)).to eq(data)
    end
  end

  describe '#close_key' do
    let(:handle)                   { double('Handle') }
    let(:close_key_request_packet) { double('CloseKey Request Packet') }
    let(:response)                 { double('Response') }
    let(:close_key_response)       { double('CloseKey Response') }
    before :example do
      allow(described_class::CloseKeyRequest).to receive(:new).and_return(close_key_request_packet)
      allow(winreg).to receive(:dcerpc_request).and_return(response)
      allow(described_class::CloseKeyResponse).to receive(:read).and_return(close_key_response)
      allow(close_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_SUCCESS)
    end

    it 'create the expected CloseKeyRequest packet' do
      winreg.close_key(handle)
      expect(described_class::CloseKeyRequest).to have_received(:new).with(hkey: handle)
    end

    it 'sends the expected dcerpc request' do
      winreg.close_key(handle)
      expect(winreg).to have_received(:dcerpc_request).with(close_key_request_packet)
    end

    it 'creates a CloseKeyResponse structure from the expected dcerpc response' do
      winreg.close_key(handle)
      expect(described_class::CloseKeyResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::CloseKeyResponse).to receive(:read).and_raise(IOError)
        expect { winreg.close_key(handle) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(close_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { winreg.close_key(handle) }.to raise_error(RubySMB::Dcerpc::Error::WinregError)
      end
    end

    it 'returns the expected error status' do
      expect(winreg.close_key(handle)).to eq(WindowsError::Win32::ERROR_SUCCESS)
    end
  end

  describe '#query_info_key' do
    let(:handle)                        { double('Handle') }
    let(:query_info_key_request_packet) { double('CloseKey Request Packet') }
    let(:response)                      { double('Response') }
    let(:query_info_key_response)       { double('CloseKey Response') }
    let(:lp_class)                      { double('LpClass') }
    let(:lp_class_referent)             { double('LpClass referent') }
    let(:lp_class_buf_ref)              { double('LpClass buffer referent') }
    before :example do
      allow(described_class::QueryInfoKeyRequest).to receive(:new).and_return(query_info_key_request_packet)
      allow(query_info_key_request_packet).to receive_messages(
        :lp_class= => nil,
        :lp_class  => lp_class,
      )
      allow(lp_class).to receive(:referent).and_return(lp_class_referent)
      allow(lp_class_referent).to receive(:actual_count=)
      allow(lp_class).to receive(:maximum_length=)
      allow(lp_class).to receive_message_chain(:buffer, :referent => lp_class_buf_ref)
      allow(lp_class_buf_ref).to receive(:max_count=)
      allow(winreg).to receive(:dcerpc_request).and_return(response)
      allow(described_class::QueryInfoKeyResponse).to receive(:read).and_return(query_info_key_response)
      allow(query_info_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_SUCCESS)
    end

    it 'create the expected QueryInfoKeyRequest packet' do
      winreg.query_info_key(handle)
      expect(described_class::QueryInfoKeyRequest).to have_received(:new).with(hkey: handle)
    end

    it 'sends the expected dcerpc request' do
      winreg.query_info_key(handle)
      expect(winreg).to have_received(:dcerpc_request).with(query_info_key_request_packet)
    end

    it 'sets the expected fields on the request packet' do
      winreg.query_info_key(handle)
      expect(query_info_key_request_packet).to have_received(:lp_class=).with('')
      expect(lp_class_referent).to have_received(:actual_count=).with(0)
      expect(lp_class).to have_received(:maximum_length=).with(1024)
      expect(lp_class_buf_ref).to have_received(:max_count=).with(1024 / 2)
    end

    it 'creates a QueryInfoKeyResponse structure from the expected dcerpc response' do
      winreg.query_info_key(handle)
      expect(described_class::QueryInfoKeyResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::QueryInfoKeyResponse).to receive(:read).and_raise(IOError)
        expect { winreg.query_info_key(handle) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(query_info_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { winreg.query_info_key(handle) }.to raise_error(RubySMB::Dcerpc::Error::WinregError)
      end
    end

    it 'returns the expected response' do
      expect(winreg.query_info_key(handle)).to eq(query_info_key_response)
    end
  end

  describe '#enum_key' do
    let(:handle)                   { double('Handle') }
    let(:index)                    { double('Index') }
    let(:enum_key_request_packet)  { double('enum_key Request Packet') }
    let(:lp_name)                  { double('Lp Name') }
    let(:buffer)                   { double('Buffer') }
    let(:lp_name_buffer_referent)  { double('Lp Name buffer referent') }
    let(:response)                 { double('Response') }
    let(:enum_key_response)        { double('enum_key Response') }
    let(:result_str)               { double('Result String') }
    let(:lp_class)                 { double('Lp Class') }
    let(:lp_class_buffer_referent) { double('Lp Class buffer referent') }
    before :example do
      allow(described_class::EnumKeyRequest).to receive(:new).and_return(enum_key_request_packet)
      allow(enum_key_request_packet).to receive_messages(
        :lpft_last_write_time= => nil,
        :lp_class=             => nil,
        :lp_name               => lp_name,
        :lp_class              => lp_class
      )
      allow(lp_class).to receive(:referent).and_return(lp_class_buffer_referent)
      allow(lp_class_buffer_referent).to receive(:buffer=)
      allow(lp_name).to receive(:buffer).and_return(buffer)
      allow(lp_name).to receive(:buffer=)
      allow(buffer).to receive(:referent).and_return(lp_name_buffer_referent)
      allow(lp_name_buffer_referent).to receive(:max_count=)
      allow(winreg).to receive(:dcerpc_request).and_return(response)
      allow(described_class::EnumKeyResponse).to receive(:read).and_return(enum_key_response)
      allow(enum_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_SUCCESS)
      allow(enum_key_response).to receive_message_chain(:lp_name, :to_s => result_str)
    end

    it 'create the expected EnumKeyRequest packet' do
      winreg.enum_key(handle, index)
      expect(described_class::EnumKeyRequest).to have_received(:new).with(hkey: handle, dw_index: index)
    end

    it 'sets the expected parameters on the request packet' do
      winreg.enum_key(handle, index)
      expect(enum_key_request_packet).to have_received(:lpft_last_write_time=).with(0)
      expect(enum_key_request_packet).to have_received(:lp_class=).with('')
      expect(lp_class_buffer_referent).to have_received(:buffer=).with(:null)
      expect(lp_name).to have_received(:buffer=).with('')
      expect(lp_name_buffer_referent).to have_received(:max_count=).with(256)
    end

    it 'sends the expected dcerpc request' do
      winreg.enum_key(handle, index)
      expect(winreg).to have_received(:dcerpc_request).with(enum_key_request_packet)
    end

    it 'creates a EnumKeyResponse structure from the expected dcerpc response' do
      winreg.enum_key(handle, index)
      expect(described_class::EnumKeyResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::EnumKeyResponse).to receive(:read).and_raise(IOError)
        expect { winreg.enum_key(handle, index) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(enum_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { winreg.enum_key(handle, index) }.to raise_error(RubySMB::Dcerpc::Error::WinregError)
      end
    end

    it 'returns the expected key name' do
      expect(winreg.enum_key(handle, index)).to eq(result_str)
    end
  end

  describe '#enum_value' do
    let(:handle)                    { double('Handle') }
    let(:index)                     { double('Index') }
    let(:enum_value_request_packet) { double('EnumValue Request Packet') }
    let(:lp_value_name)             { double('Lp Value Name') }
    let(:buffer)                    { double('Buffer') }
    let(:referent)                  { double('Referent') }
    let(:response)                  { double('Response') }
    let(:enum_value_response)       { double('EnumValue Response') }
    let(:result_str)                { double('Result String') }
    before :example do
      allow(described_class::EnumValueRequest).to receive(:new).and_return(enum_value_request_packet)
      allow(enum_value_request_packet).to receive(:lp_value_name).and_return(lp_value_name)
      allow(lp_value_name).to receive(:buffer).and_return(buffer)
      allow(lp_value_name).to receive(:buffer=)
      allow(buffer).to receive(:referent).and_return(referent)
      allow(referent).to receive(:max_count=)
      allow(winreg).to receive(:dcerpc_request).and_return(response)
      allow(described_class::EnumValueResponse).to receive(:read).and_return(enum_value_response)
      allow(enum_value_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_SUCCESS)
      allow(enum_value_response).to receive_message_chain(:lp_value_name, :to_s => result_str)
    end

    it 'create the expected EnumValueRequest packet' do
      winreg.enum_value(handle, index)
      expect(described_class::EnumValueRequest).to have_received(:new).with(hkey: handle, dw_index: index)
    end

    it 'sets the expected buffer on the request packet' do
      winreg.enum_value(handle, index)
      expect(referent).to have_received(:max_count=).with(256)
      expect(lp_value_name).to have_received(:buffer=).with('')
    end

    it 'sends the expected dcerpc request' do
      winreg.enum_value(handle, index)
      expect(winreg).to have_received(:dcerpc_request).with(enum_value_request_packet)
    end

    it 'creates a EnumValueResponse structure from the expected dcerpc response' do
      winreg.enum_value(handle, index)
      expect(described_class::EnumValueResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::EnumValueResponse).to receive(:read).and_raise(IOError)
        expect { winreg.enum_value(handle, index) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(enum_value_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { winreg.enum_value(handle, index) }.to raise_error(RubySMB::Dcerpc::Error::WinregError)
      end
    end

    it 'returns the expected key name' do
      expect(winreg.enum_value(handle, index)).to eq(result_str)
    end
  end

  describe '#has_registry_key?' do
    let(:root_key)        { 'HKLM' }
    let(:sub_key)         { 'my\\sub\\key\\path' }
    let(:key)             { "#{root_key}\\#{sub_key}" }
    let(:root_key_handle) { double('Root Key Handle') }
    let(:subkey_handle)   { double('Subkey Handle') }
    before :example do
      allow(winreg).to receive_messages(
        :bind          => nil,
        :open_root_key => root_key_handle,
        :open_key      => subkey_handle,
        :close_key     => nil
      )
    end

    it 'binds a DCERPC connection to the expected remote endpoint' do
      winreg.has_registry_key?(key)
      expect(winreg).to have_received(:bind).with(endpoint: RubySMB::Dcerpc::Winreg)
    end

    it 'does not bind a DCERPC connection if #bind argument is false' do
      winreg.has_registry_key?(key, bind: false)
      expect(winreg).to_not have_received(:bind)
    end

    it 'opens the expected root key' do
      winreg.has_registry_key?(key)
      expect(winreg).to have_received(:open_root_key).with(root_key)
    end

    it 'opens the expected registry key' do
      winreg.has_registry_key?(key)
      expect(winreg).to have_received(:open_key).with(root_key_handle, sub_key)
    end

    context 'when a WinregError occurs while opening the root key' do
      it 'returns false' do
        allow(winreg).to receive(:open_root_key).and_raise(RubySMB::Dcerpc::Error::WinregError)
        expect(winreg.has_registry_key?(key)).to be false
      end
    end

    context 'when a WinregError occurs while opening the registry key' do
      it 'returns false' do
        allow(winreg).to receive(:open_key).and_raise(RubySMB::Dcerpc::Error::WinregError)
        expect(winreg.has_registry_key?(key)).to be false
      end
    end

    it 'closes the key' do
      winreg.has_registry_key?(key)
      expect(winreg).to have_received(:close_key).with(subkey_handle)
      expect(winreg).to have_received(:close_key).with(root_key_handle)
    end

    it 'returns true when no error occurs' do
      expect(winreg.has_registry_key?(key)).to be true
    end
  end

  describe '#read_registry_key_value' do
    let(:root_key)        { 'HKLM' }
    let(:sub_key)         { 'my\\sub\\key\\path' }
    let(:key)             { "#{root_key}\\#{sub_key}" }
    let(:value_name)      { 'registry_value_name' }
    let(:root_key_handle) { double('Root Key Handle') }
    let(:subkey_handle)   { double('Subkey Handle') }
    let(:value)           { double('Value') }
    before :example do
      allow(winreg).to receive_messages(
        :bind          => nil,
        :open_root_key => root_key_handle,
        :open_key      => subkey_handle,
        :query_value   => value,
        :close_key     => nil
      )
    end

    it 'binds a DCERPC connection to the expected remote endpoint' do
      winreg.read_registry_key_value(key, value_name)
      expect(winreg).to have_received(:bind).with(endpoint: RubySMB::Dcerpc::Winreg)
    end

    it 'does not bind a DCERPC connection if #bind argument is false' do
      winreg.read_registry_key_value(key, value_name, bind: false)
      expect(winreg).to_not have_received(:bind)
    end

    it 'opens the expected root key' do
      winreg.read_registry_key_value(key, value_name)
      expect(winreg).to have_received(:open_root_key).with(root_key)
    end

    it 'opens the expected registry key' do
      winreg.read_registry_key_value(key, value_name)
      expect(winreg).to have_received(:open_key).with(root_key_handle, sub_key)
    end

    it 'queries the expected registry key value' do
      winreg.read_registry_key_value(key, value_name)
      expect(winreg).to have_received(:query_value).with(subkey_handle, value_name)
    end

    it 'closes the key' do
      winreg.read_registry_key_value(key, value_name)
      expect(winreg).to have_received(:close_key).with(subkey_handle)
      expect(winreg).to have_received(:close_key).with(root_key_handle)
    end

    it 'returns expect registry key value' do
      expect(winreg.read_registry_key_value(key, value_name)).to eq(value)
    end
  end

  describe '#enum_registry_key' do
    let(:root_key)                  { 'HKLM' }
    let(:sub_key)                   { 'my\\sub\\key\\path' }
    let(:key)                       { "#{root_key}\\#{sub_key}" }
    let(:value_name)                { 'registry_value_name' }
    let(:root_key_handle)           { double('Root Key Handle') }
    let(:subkey_handle)             { double('Subkey Handle') }
    let(:query_info_key_response)   { double('Query Info Key Response') }
    let(:subkey_nb)                 { 2 }
    before :example do
      allow(winreg).to receive_messages(
        :bind           => nil,
        :open_root_key  => root_key_handle,
        :open_key       => subkey_handle,
        :query_info_key => query_info_key_response,
        :enum_key       => nil,
        :close_key      => nil
      )
      allow(query_info_key_response).to receive(:lpc_sub_keys).and_return(subkey_nb)
    end

    it 'binds a DCERPC connection to the expected remote endpoint' do
      winreg.enum_registry_key(key)
      expect(winreg).to have_received(:bind).with(endpoint: RubySMB::Dcerpc::Winreg)
    end

    it 'does not bind a DCERPC connection if #bind argument is false' do
      winreg.enum_registry_key(key, bind: false)
      expect(winreg).to_not have_received(:bind)
    end

    it 'opens the expected root key' do
      winreg.enum_registry_key(key)
      expect(winreg).to have_received(:open_root_key).with(root_key)
    end

    context 'when the registry key only contains the root key' do
      it 'queries information for the root key' do
        winreg.enum_registry_key(root_key)
        expect(winreg).to have_received(:query_info_key).with(root_key_handle)
      end
    end

    it 'opens the expected registry key' do
      winreg.enum_registry_key(key)
      expect(winreg).to have_received(:open_key).with(root_key_handle, sub_key)
    end

    it 'queries information for the expected registry key' do
      winreg.enum_registry_key(key)
      expect(winreg).to have_received(:query_info_key).with(subkey_handle)
    end

    it 'calls #enum_key the expected number of times' do
      winreg.enum_registry_key(key)
      expect(winreg).to have_received(:enum_key).with(subkey_handle, instance_of(Fixnum)).twice
    end

    it 'closes the key' do
      winreg.enum_registry_key(key)
      expect(winreg).to have_received(:close_key).with(subkey_handle)
      expect(winreg).to have_received(:close_key).with(root_key_handle)
    end

    it 'returns the expected array of enumerated keys' do
      key1 = 'key1'
      key2 = 'key2'
      allow(winreg).to receive(:enum_key).with(subkey_handle, 0).and_return(key1)
      allow(winreg).to receive(:enum_key).with(subkey_handle, 1).and_return(key2)
      expect(winreg.enum_registry_key(key)).to eq([key1, key2])
    end
  end

  describe '#enum_registry_values' do
    let(:root_key)                  { 'HKLM' }
    let(:sub_key)                   { 'my\\sub\\key\\path' }
    let(:key)                       { "#{root_key}\\#{sub_key}" }
    let(:value_name)                { 'registry_value_name' }
    let(:root_key_handle)           { double('Root Key Handle') }
    let(:subkey_handle)             { double('Subkey Handle') }
    let(:query_info_key_response)   { double('Query Info Key Response') }
    let(:subkey_nb)                 { 2 }
    before :example do
      allow(winreg).to receive_messages(
        :bind           => nil,
        :open_root_key  => root_key_handle,
        :open_key       => subkey_handle,
        :query_info_key => query_info_key_response,
        :enum_value     => nil,
        :close_key      => nil
      )
      allow(query_info_key_response).to receive(:lpc_values).and_return(subkey_nb)
    end

    it 'binds a DCERPC connection to the expected remote endpoint' do
      winreg.enum_registry_values(key)
      expect(winreg).to have_received(:bind).with(endpoint: RubySMB::Dcerpc::Winreg)
    end

    it 'does not bind a DCERPC connection if #bind argument is false' do
      winreg.enum_registry_values(key, bind: false)
      expect(winreg).to_not have_received(:bind)
    end

    it 'opens the expected root key' do
      winreg.enum_registry_values(key)
      expect(winreg).to have_received(:open_root_key).with(root_key)
    end

    context 'when the registry key only contains the root key' do
      it 'queries information for the root key' do
        winreg.enum_registry_values(root_key)
        expect(winreg).to have_received(:query_info_key).with(root_key_handle)
      end
    end

    it 'opens the expected registry key' do
      winreg.enum_registry_values(key)
      expect(winreg).to have_received(:open_key).with(root_key_handle, sub_key)
    end

    it 'queries information for the expected registry key' do
      winreg.enum_registry_values(key)
      expect(winreg).to have_received(:query_info_key).with(subkey_handle)
    end

    it 'calls #enum_key the expected number of times' do
      winreg.enum_registry_values(key)
      expect(winreg).to have_received(:enum_value).with(subkey_handle, instance_of(Fixnum)).twice
    end

    it 'closes the key' do
      winreg.enum_registry_values(key)
      expect(winreg).to have_received(:close_key).with(subkey_handle)
      expect(winreg).to have_received(:close_key).with(root_key_handle)
    end

    it 'returns the expected array of enumerated keys' do
      value1 = 'value1'
      value2 = 'value2'
      allow(winreg).to receive(:enum_value).with(subkey_handle, 0).and_return(value1)
      allow(winreg).to receive(:enum_value).with(subkey_handle, 1).and_return(value2)
      expect(winreg.enum_registry_values(key)).to eq([value1, value2])
    end
  end

  describe '#create_key' do
    let(:handle)              { double('Handle') }
    let(:sub_key)             { double('Sub key') }
    let(:create_key_request)  { double('CreateKey Request') }
    let(:response)            { double('Response') }
    let(:create_key_response) { double('CreateKey Response') }
    let(:hkey)                { double('hkey') }
    before :example do
      allow(described_class::CreateKeyRequest).to receive(:new).and_return(create_key_request)
      allow(winreg).to receive(:dcerpc_request).and_return(response)
      allow(described_class::CreateKeyResponse).to receive(:read).and_return(create_key_response)
      allow(create_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_SUCCESS)
      allow(create_key_response).to receive(:hkey).and_return(hkey)
    end

    it 'create the expected CreateKeyRequest packet with the default options' do
      opts = {
        hkey:                   handle,
        lp_sub_key:             sub_key,
        lp_class:               :null,
        dw_options:             RubySMB::Dcerpc::Winreg::CreateKeyRequest::REG_KEY_TYPE_VOLATILE,
        sam_desired:            RubySMB::Dcerpc::Winreg::Regsam.new(maximum: 1),
        lp_security_attributes: RubySMB::Dcerpc::RpcSecurityAttributes.new,
        lpdw_disposition:       RubySMB::Dcerpc::Winreg::CreateKeyRequest::REG_CREATED_NEW_KEY
      }
      winreg.create_key(handle, sub_key)
      expect(described_class::CreateKeyRequest).to have_received(:new).with(opts)
    end

    it 'create the expected CreateKeyRequest packet with custom options' do
      opts = {
        hkey:                  handle,
        lp_sub_key:            sub_key,
        lp_class:              'MyClass',
        dw_options:             RubySMB::Dcerpc::Winreg::CreateKeyRequest::REG_KEY_TYPE_SYMLINK,
        sam_desired:            RubySMB::Dcerpc::Winreg::Regsam.new(key_set_value: 1),
        lp_security_attributes: RubySMB::Dcerpc::RpcSecurityAttributes.new(n_length: 3),
        lpdw_disposition:       RubySMB::Dcerpc::Winreg::CreateKeyRequest::REG_OPENED_EXISTING_KEY
      }
      winreg.create_key(handle, sub_key, opts)
      expect(described_class::CreateKeyRequest).to have_received(:new).with(opts)
    end

    it 'sends the expected dcerpc request' do
      winreg.create_key(handle, sub_key)
      expect(winreg).to have_received(:dcerpc_request).with(create_key_request)
    end

    it 'creates a CreateKeyResponse structure from the expected dcerpc response' do
      winreg.create_key(handle, sub_key)
      expect(described_class::CreateKeyResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::CreateKeyResponse).to receive(:read).and_raise(IOError)
        expect { winreg.create_key(handle, sub_key) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(create_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { winreg.create_key(handle, sub_key) }.to raise_error(RubySMB::Dcerpc::Error::WinregError)
      end
    end

    it 'returns the expected key name' do
      expect(winreg.create_key(handle, sub_key)).to eq(hkey)
    end
  end

  describe '#save_key' do
    let(:handle)              { double('Handle') }
    let(:filename)            { double('Filename') }
    let(:save_key_request)    { double('CreateKey Request') }
    let(:response)            { double('Response') }
    let(:save_key_response)   { double('CreateKey Response') }
    let(:hkey)                { double('hkey') }
    before :example do
      allow(described_class::SaveKeyRequest).to receive(:new).and_return(save_key_request)
      allow(winreg).to receive(:dcerpc_request).and_return(response)
      allow(described_class::SaveKeyResponse).to receive(:read).and_return(save_key_response)
      allow(save_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_SUCCESS)
    end

    it 'create the expected SaveKeyRequest packet with the default options' do
      opts = {
        hkey:                   handle,
        lp_file:                filename,
        lp_security_attributes: :null,
      }
      winreg.save_key(handle, filename)
      expect(described_class::SaveKeyRequest).to have_received(:new).with(opts)
    end

    it 'create the expected SaveKeyRequest packet with custom options' do
      opts = {
        hkey:                   handle,
        lp_file:                filename,
        lp_security_attributes: RubySMB::Dcerpc::RpcSecurityAttributes.new,
      }
      winreg.save_key(handle, filename, opts)
      expect(described_class::SaveKeyRequest).to have_received(:new).with(opts)
    end

    it 'sends the expected dcerpc request' do
      winreg.save_key(handle, filename)
      expect(winreg).to have_received(:dcerpc_request).with(save_key_request)
    end

    it 'creates a SaveKeyResponse structure from the expected dcerpc response' do
      winreg.save_key(handle, filename)
      expect(described_class::SaveKeyResponse).to have_received(:read).with(response)
    end

    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::SaveKeyResponse).to receive(:read).and_raise(IOError)
        expect { winreg.save_key(handle, filename) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end

    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(save_key_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { winreg.save_key(handle, filename) }.to raise_error(RubySMB::Dcerpc::Error::WinregError)
      end
    end
  end
end
