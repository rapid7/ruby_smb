RSpec.describe RubySMB::Dcerpc::Samr do
  let(:samr) do
    RubySMB::SMB1::Pipe.new(
      tree: double('Tree'),
      response: RubySMB::SMB1::Packet::NtCreateAndxResponse.new,
      name: 'samr'
    )
  end

  describe described_class::SamprRidEnumeration do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :relative_id }
    it { is_expected.to respond_to :name }

    it 'is little endian' do
      expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
    end
    it 'is a Ndr::NdrStruct' do
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::NdrStruct)
    end
    it 'is four-byte aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    describe '#relative_id' do
      it 'is a NdrUint32 structure' do
        expect(packet.relative_id).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#name' do
      it 'is a RpcUnicodeString structure' do
        expect(packet.name).to be_a RubySMB::Dcerpc::RpcUnicodeString
      end
    end
    it 'reads itself' do
      new_packet = described_class.new(relative_id: 4, name: 'Test String')
      expected_output = {
        relative_id: 4,
        name: {
           buffer_length: 22,
           maximum_length: 22,
           buffer: "Test String".encode('utf-16le')
        }
      }
      expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
    end
  end

  describe described_class::SamprRidEnumerationArray do
    subject(:packet) { described_class.new }

    it 'is a Ndr::NdrConfArray' do
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::NdrConfArray)
    end
    it 'has element of type SamprRidEnumeration' do
      packet << {relative_id: 4, name: ''}
      expect(packet[0]).to be_a(RubySMB::Dcerpc::Samr::SamprRidEnumeration)
    end
    it 'reads itself' do
      new_packet = described_class.new([
        {relative_id: 4, name: 'Test1'},
        {relative_id: 1, name: 'Test2'}
      ])
      expected_output = [
      {
        relative_id: 4,
        name: {
           buffer_length: 10,
           maximum_length: 10,
           buffer: "Test1".encode('utf-16le')
        }
      },
      {
        relative_id: 1,
        name: {
           buffer_length: 10,
           maximum_length: 10,
           buffer: "Test2".encode('utf-16le')
        }
      }]
      expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
    end
  end

  describe described_class::PsamprRidEnumerationArray do
    subject(:packet) { described_class.new }

    it 'is a SamprRidEnumerationArray' do
      expect(packet).to be_a(RubySMB::Dcerpc::Samr::SamprRidEnumerationArray)
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'is four-byte aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    it 'reads itself' do
      new_packet = described_class.new([
        {relative_id: 4, name: 'Test1'},
        {relative_id: 1, name: 'Test2'}
      ])
      expected_output = [
      {
        relative_id: 4,
        name: {
           buffer_length: 10,
           maximum_length: 10,
           buffer: "Test1".encode('utf-16le')
        }
      },
      {
        relative_id: 1,
        name: {
           buffer_length: 10,
           maximum_length: 10,
           buffer: "Test2".encode('utf-16le')
        }
      }]
      expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
    end
  end

  describe described_class::SamprEnumerationBuffer do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :entries_read }
    it { is_expected.to respond_to :buffer }

    it 'is little endian' do
      expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
    end
    it 'is a Ndr::NdrStruct' do
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::NdrStruct)
    end
    it 'is four-byte aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    describe '#entries_read' do
      it 'is a NdrUint32 structure' do
        expect(packet.entries_read).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#buffer' do
      it 'is a PsamprRidEnumerationArray structure' do
        expect(packet.buffer).to be_a RubySMB::Dcerpc::Samr::PsamprRidEnumerationArray
      end
    end
    it 'reads itself' do
      new_packet = described_class.new(
        entries_read: 3,
        buffer: [
          { relative_id: 500, name: "Administrator" },
          { relative_id: 501, name: "Guest" },
          { relative_id: 1001, name: "WIN-DP0M1BC768$" }
        ]
      )
      expected_output = {
        entries_read: 3,
        buffer: [
          {relative_id: 500, name: { buffer_length: 26, maximum_length: 26, buffer: "Administrator".encode('utf-16le') }},
          {relative_id: 501, name: { buffer_length: 10, maximum_length: 10, buffer: "Guest".encode('utf-16le') }},
          {relative_id: 1001, name: { buffer_length: 30, maximum_length: 30, buffer: "WIN-DP0M1BC768$".encode('utf-16le') }}
        ]
      }
      expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
    end
  end

  describe described_class::PsamprEnumerationBuffer do
    subject(:packet) { described_class.new }

    it 'is a SamprEnumerationBuffer' do
      expect(packet).to be_a(RubySMB::Dcerpc::Samr::SamprEnumerationBuffer)
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'is four-byte aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    it 'reads itself' do
      new_packet = described_class.new(
        entries_read: 3,
        buffer: [
          { relative_id: 500, name: "Administrator" },
          { relative_id: 501, name: "Guest" },
          { relative_id: 1001, name: "WIN-DP0M1BC768$" }
        ]
      )
      expected_output = {
        entries_read: 3,
        buffer: [
          {relative_id: 500, name: { buffer_length: 26, maximum_length: 26, buffer: "Administrator".encode('utf-16le') }},
          {relative_id: 501, name: { buffer_length: 10, maximum_length: 10, buffer: "Guest".encode('utf-16le') }},
          {relative_id: 1001, name: { buffer_length: 30, maximum_length: 30, buffer: "WIN-DP0M1BC768$".encode('utf-16le') }}
        ]
      }
      expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
    end
  end

  describe described_class::SamprHandle do
    it 'is a Ndr::NdrContextHandle' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
    end
  end

  describe '#samr_connect' do
    let(:samr_connect_request) { double('SamrConnectRequest') }
    let(:response) { double('Response') }
    let(:samr_connect_response) { double('SamrConnectResponse') }
    let(:server_handle) { double('server_handle') }
    before :example do
      allow(described_class::SamrConnectRequest).to receive(:new).and_return(samr_connect_request)
      allow(samr).to receive(:dcerpc_request).and_return(response)
      allow(described_class::SamrConnectResponse).to receive(:read).and_return(samr_connect_response)
      allow(samr_connect_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :server_handle => server_handle
      )
    end

    it 'sets the request with the expected values' do
      samr.samr_connect(server_name: 'TestServer')
      expect(described_class::SamrConnectRequest).to have_received(:new).with(
        server_name: 'TestServer',
        desired_access: described_class::MAXIMUM_ALLOWED
      )
    end
    it 'send the expected request structure' do
      samr.samr_connect
      expect(samr).to have_received(:dcerpc_request).with(samr_connect_request)
    end
    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::SamrConnectResponse).to receive(:read).and_raise(IOError)
        expect { samr.samr_connect }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(samr_connect_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { samr.samr_connect }.to raise_error(RubySMB::Dcerpc::Error::SamrError)
      end
    end
    it 'returns the expected handler' do
      expect(samr.samr_connect).to eq(server_handle)
    end
    context 'with a real binary stream' do
      it 'returns the expected value' do
        raw_response = "\x00\x00\x00\x00\xFCF\xAC\x19F\xF5\x9EF\x8E\x9A\x8C\xAC\x0FG\x18\xD8\x00\x00\x00\x00"
        allow(samr).to receive(:dcerpc_request).and_return(raw_response)
        allow(described_class::SamrConnectResponse).to receive(:read).and_call_original
        expect(samr.samr_connect).to eq({:context_handle_attributes=>0, :context_handle_uuid=>"19ac46fc-f546-469e-8e9a-8cac0f4718d8"})
      end
    end
  end

  describe '#samr_lookup_domain' do
    let(:server_handle) { double('server_handle') }
    let(:samr_lookup_domain_request) { double('SamrLookupDomainInSamServerRequest') }
    let(:response) { double('Response') }
    let(:samr_lookup_domain_response) { double('SamrLookupDomainInSamServerResponse') }
    let(:domain_id) { double('domain_id') }
    before :example do
      allow(described_class::SamrLookupDomainInSamServerRequest).to receive(:new).and_return(samr_lookup_domain_request)
      allow(samr).to receive(:dcerpc_request).and_return(response)
      allow(described_class::SamrLookupDomainInSamServerResponse).to receive(:read).and_return(samr_lookup_domain_response)
      allow(samr_lookup_domain_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :domain_id => domain_id
      )
    end

    it 'sets the request with the expected values' do
      samr.samr_lookup_domain(server_handle: server_handle, name: 'My Name')
      expect(described_class::SamrLookupDomainInSamServerRequest).to have_received(:new).with(
        server_handle: server_handle,
        name: 'My Name'
      )
    end
    it 'send the expected request structure' do
      samr.samr_lookup_domain(server_handle: server_handle, name: '')
      expect(samr).to have_received(:dcerpc_request).with(samr_lookup_domain_request)
    end
    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::SamrLookupDomainInSamServerResponse).to receive(:read).and_raise(IOError)
        expect { samr.samr_lookup_domain(server_handle: server_handle, name: '') }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(samr_lookup_domain_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { samr.samr_lookup_domain(server_handle: server_handle, name: '') }.to raise_error(RubySMB::Dcerpc::Error::SamrError)
      end
    end
    it 'returns the expected handler' do
      expect(samr.samr_lookup_domain(server_handle: server_handle, name: '')).to eq(domain_id)
    end
    context 'with a real binary stream' do
      it 'returns the expected value' do
        raw_response =
          "\x00\x00\x02\x00\x04\x00\x00\x00"\
          "\x01\x04\x00\x00\x00\x00\x00\x05"\
          "\x15\x00\x00\x00~\xC7\x01\x19TU"\
          "\x90\x00\xA0\xD8\xF8\xF3\x00\x00\x00\x00"
        allow(samr).to receive(:dcerpc_request).and_return(raw_response)
        allow(described_class::SamrLookupDomainInSamServerResponse).to receive(:read).and_call_original
        expect(samr.samr_lookup_domain(server_handle: server_handle, name: '')).to eq(
          "S-1-5-21-419547006-9459028-4093171872"
        )
      end
    end
  end

  describe '#samr_open_domain' do
    let(:server_handle) { double('server_handle') }
    let(:domain_id) { double('domain_id') }
    let(:samr_open_domain_request) { double('SamrOpenDomainRequest') }
    let(:response) { double('Response') }
    let(:samr_open_domain_response) { double('SamrOpenDomainResponse') }
    let(:domain_handle) { double('domain_handle') }
    before :example do
      allow(described_class::SamrOpenDomainRequest).to receive(:new).and_return(samr_open_domain_request)
      allow(samr).to receive(:dcerpc_request).and_return(response)
      allow(described_class::SamrOpenDomainResponse).to receive(:read).and_return(samr_open_domain_response)
      allow(samr_open_domain_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :domain_handle => domain_handle
      )
    end

    it 'sets the request with the expected values' do
      samr.samr_open_domain(server_handle: server_handle, domain_id: domain_id)
      expect(described_class::SamrOpenDomainRequest).to have_received(:new).with(
        server_handle: server_handle,
        desired_access: described_class::MAXIMUM_ALLOWED,
        domain_id: domain_id
      )
    end
    it 'send the expected request structure' do
      samr.samr_open_domain(server_handle: server_handle, domain_id: domain_id)
      expect(samr).to have_received(:dcerpc_request).with(samr_open_domain_request)
    end
    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::SamrOpenDomainResponse).to receive(:read).and_raise(IOError)
        expect { samr.samr_open_domain(server_handle: server_handle, domain_id: domain_id) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(samr_open_domain_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { samr.samr_open_domain(server_handle: server_handle, domain_id: domain_id) }.to raise_error(RubySMB::Dcerpc::Error::SamrError)
      end
    end
    it 'returns the expected handler' do
      expect(samr.samr_open_domain(server_handle: server_handle, domain_id: domain_id)).to eq(domain_handle)
    end
    context 'with a real binary stream' do
      it 'returns the expected value' do
        raw_response = "\x00\x00\x00\x00\xC3\x9C\xFEe\xB5\xBA{K\x96<v\x82\x156S\xAA\x00\x00\x00\x00"
        allow(samr).to receive(:dcerpc_request).and_return(raw_response)
        allow(described_class::SamrOpenDomainResponse).to receive(:read).and_call_original
        expect(samr.samr_open_domain(server_handle: server_handle, domain_id: domain_id)).to eq(
          {:context_handle_attributes=>0, :context_handle_uuid=>"65fe9cc3-bab5-4b7b-963c-7682153653aa"}
        )
      end
    end
  end

  describe '#samr_enumerate_users_in_domain' do
    let(:domain_handle) { double('domain_handle') }
    let(:enumeration_context) { double('enumeration_context') }
    let(:user_account_control) { double('user_account_control') }
    let(:samr_enumerate_users_in_domain_request) { double('SamrEnumerateUsersInDomainRequest') }
    let(:response) { double('Response') }
    let(:samr_enumerate_users_in_domain_response) { double('SamrEnumerateUsersInDomainResponse') }
    let(:entry1) { double('entry1') }
    let(:entry2) { double('entry2') }
    let(:entries) { [entry1, entry2] }
    before :example do
      allow(described_class::SamrEnumerateUsersInDomainRequest).to receive(:new).and_return(samr_enumerate_users_in_domain_request)
      allow(samr_enumerate_users_in_domain_request).to receive(:enumeration_context=)
      allow(samr_enumerate_users_in_domain_request).to receive(:enumeration_context).and_return(enumeration_context)
      allow(samr).to receive(:dcerpc_request).and_return(response)
      allow(described_class::SamrEnumerateUsersInDomainResponse).to receive(:read).and_return(samr_enumerate_users_in_domain_response)
      allow(samr_enumerate_users_in_domain_response).to receive(:error_status).and_return(WindowsError::NTStatus::STATUS_SUCCESS)
      allow(samr_enumerate_users_in_domain_response).to receive_message_chain(:buffer, :buffer => entries)
      allow(entry1).to receive(:relative_id).and_return(501)
      allow(entry2).to receive(:relative_id).and_return(502)
      allow(entry1).to receive_message_chain(:name, :buffer => 'Entry 1')
      allow(entry2).to receive_message_chain(:name, :buffer => 'Entry 2')
    end

    it 'sets the request with the expected values' do
      samr.samr_enumerate_users_in_domain(
        domain_handle: domain_handle,
        enumeration_context: enumeration_context,
        user_account_control: user_account_control
      )
      expect(described_class::SamrEnumerateUsersInDomainRequest).to have_received(:new).with(
        domain_handle: domain_handle,
        user_account_control: user_account_control,
        prefered_maximum_length: 0xFFFFFFFF
      )
      expect(samr_enumerate_users_in_domain_request).to have_received(:enumeration_context=).with(enumeration_context)
    end
    it 'send the expected request structure' do
      samr.samr_enumerate_users_in_domain(domain_handle: domain_handle)
      expect(samr).to have_received(:dcerpc_request).with(samr_enumerate_users_in_domain_request)
    end
    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::SamrEnumerateUsersInDomainResponse).to receive(:read).and_raise(IOError)
        expect { samr.samr_enumerate_users_in_domain(domain_handle: domain_handle) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response error status is not ERROR_SUCCESS or STATUS_MORE_ENTRIES' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(samr_enumerate_users_in_domain_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { samr.samr_enumerate_users_in_domain(domain_handle: domain_handle) }.to raise_error(RubySMB::Dcerpc::Error::SamrError)
      end
    end
    it 'returns the expected handler' do
      expect(samr.samr_enumerate_users_in_domain(domain_handle: domain_handle)).to eq({
        501 => 'Entry 1',
        502 => 'Entry 2'
      })
    end
    context 'with a real binary stream' do
      it 'returns the expected value' do
        raw_response =
          "\x00\x00\x00\x00\x00\x00\x02\x00\x06\x00\x00\x00\x04\x00\x02\x00"\
          "\x06\x00\x00\x00\xF4\x01\x00\x00\x1A\x00\x1A\x00\b\x00\x02\x00\xF5"\
          "\x01\x00\x00\n\x00\n\x00\f\x00\x02\x00\xF6\x01\x00\x00\f\x00\f\x00"\
          "\x10\x00\x02\x00Q\x04\x00\x00\x10\x00\x10\x00\x14\x00\x02\x00\xE9\x03"\
          "\x00\x00\x1E\x00\x1E\x00\x18\x00\x02\x00P\x04\x00\x00 \x00 \x00\x1C"\
          "\x00\x02\x00\r\x00\x00\x00\x00\x00\x00\x00\r\x00\x00\x00A\x00d\x00m"\
          "\x00i\x00n\x00i\x00s\x00t\x00r\x00a\x00t\x00o\x00r\x00\x00\x00\x05"\
          "\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00G\x00u\x00e\x00s\x00t\x00"\
          "\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00k\x00r\x00b"\
          "\x00t\x00g\x00t\x00\b\x00\x00\x00\x00\x00\x00\x00\b\x00\x00\x00s\x00m"\
          "\x00b\x00t\x00e\x00s\x00t\x002\x00\x0F\x00\x00\x00\x00\x00\x00\x00\x0F"\
          "\x00\x00\x00W\x00I\x00N\x00-\x00D\x00P\x000\x00M\x001\x00B\x00C\x007"\
          "\x006\x008\x00$\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00"\
          "\x00\x00D\x00E\x00S\x00K\x00T\x00O\x00P\x00-\x005\x00A\x00R\x004\x00M"\
          "\x002\x00S\x00$\x00\x06\x00\x00\x00\x00\x00\x00\x00"
        allow(samr).to receive(:dcerpc_request).and_return(raw_response)
        allow(described_class::SamrEnumerateUsersInDomainResponse).to receive(:read).and_call_original
        expect(samr.samr_enumerate_users_in_domain(domain_handle: domain_handle)).to eq({
          500 => "Administrator".encode('utf-16le'),
          501 => "Guest".encode('utf-16le'),
          502 => "krbtgt".encode('utf-16le'),
          1105 => "smbtest2".encode('utf-16le'),
          1001 => "WIN-DP0M1BC768$".encode('utf-16le'),
          1104 => "DESKTOP-5AR4M2S$".encode('utf-16le')
        })
      end
    end
    context 'with a STATUS_MORE_ENTRIES response' do
      let(:enumeration_context2) { double('enumeration_context2') }
      let(:entry3) { double('entry3') }
      let(:entry4) { double('entry4') }
      let(:entries2) { [entry3, entry4] }
      before :example do
        first_pass = true
        allow(described_class::SamrEnumerateUsersInDomainResponse).to receive(:read) do
          if first_pass
            allow(samr_enumerate_users_in_domain_response).to receive(:error_status).and_return(WindowsError::NTStatus::STATUS_MORE_ENTRIES)
            allow(samr_enumerate_users_in_domain_response).to receive(:enumeration_context).and_return(enumeration_context2)
            first_pass = false
          else
            allow(samr_enumerate_users_in_domain_response).to receive(:error_status).and_return(WindowsError::NTStatus::STATUS_SUCCESS)
            allow(samr_enumerate_users_in_domain_response).to receive_message_chain(:buffer, :buffer => entries2)
          end
          samr_enumerate_users_in_domain_response
        end
        allow(entry3).to receive(:relative_id).and_return(503)
        allow(entry4).to receive(:relative_id).and_return(504)
        allow(entry3).to receive_message_chain(:name, :buffer => 'Entry 3')
        allow(entry4).to receive_message_chain(:name, :buffer => 'Entry 4')
      end
      it 'sends multiple requests with the expected enumeration_context value' do
        samr.samr_enumerate_users_in_domain(
          domain_handle: domain_handle,
          enumeration_context: enumeration_context
        )
        expect(samr).to have_received(:dcerpc_request).with(samr_enumerate_users_in_domain_request).twice
        expect(samr_enumerate_users_in_domain_request).to have_received(:enumeration_context=).with(enumeration_context)
        expect(samr_enumerate_users_in_domain_request).to have_received(:enumeration_context=).with(enumeration_context2)
      end
      it 'returns the expected hash' do
        expect(samr.samr_enumerate_users_in_domain(domain_handle: domain_handle)).to eq({
          501 => 'Entry 1',
          502 => 'Entry 2',
          503 => 'Entry 3',
          504 => 'Entry 4'
        })
      end
    end
  end

  describe '#samr_rid_to_sid' do
    let(:object_handle) { double('object_handle') }
    let(:samr_rid_to_sid_request) { double('SamrRidToSidRequest') }
    let(:response) { double('Response') }
    let(:samr_rid_to_sid_response) { double('SamrRidToSidResponse') }
    let(:sid) { double('sid') }
    before :example do
      allow(described_class::SamrRidToSidRequest).to receive(:new).and_return(samr_rid_to_sid_request)
      allow(samr).to receive(:dcerpc_request).and_return(response)
      allow(described_class::SamrRidToSidResponse).to receive(:read).and_return(samr_rid_to_sid_response)
      allow(samr_rid_to_sid_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :sid => sid
      )
    end

    it 'sets the request with the expected values' do
      samr.samr_rid_to_sid(object_handle: object_handle, rid: 501)
      expect(described_class::SamrRidToSidRequest).to have_received(:new).with(
        object_handle: object_handle,
        rid: 501
      )
    end
    it 'send the expected request structure' do
      samr.samr_rid_to_sid(object_handle: object_handle, rid: 501)
      expect(samr).to have_received(:dcerpc_request).with(samr_rid_to_sid_request)
    end
    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::SamrRidToSidResponse).to receive(:read).and_raise(IOError)
        expect { samr.samr_rid_to_sid(object_handle: object_handle, rid: 501) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(samr_rid_to_sid_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { samr.samr_rid_to_sid(object_handle: object_handle, rid: 501) }.to raise_error(RubySMB::Dcerpc::Error::SamrError)
      end
    end
    it 'returns the expected handler' do
      expect(samr.samr_rid_to_sid(object_handle: object_handle, rid: 501)).to eq(sid)
    end
    context 'with a real binary stream' do
      it 'returns the expected value' do
        raw_response =
          "\x00\x00\x02\x00\x05\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00"\
          "\x05\x15\x00\x00\x00~\xC7\x01\x19TU\x90\x00\xA0\xD8\xF8\xF3"\
          "\xF4\x01\x00\x00\x00\x00\x00\x00"
        allow(samr).to receive(:dcerpc_request).and_return(raw_response)
        allow(described_class::SamrRidToSidResponse).to receive(:read).and_call_original
        expect(samr.samr_rid_to_sid(object_handle: object_handle, rid: '')).to eq(
          "S-1-5-21-419547006-9459028-4093171872-500"
        )
      end
    end
  end

  describe '#close_handle' do
    let(:samr_close_handle_request) { double('SamrCloseHandleRequest') }
    let(:response) { double('Response') }
    let(:samr_close_handle_response) { double('SamrCloseHandleResponse') }
    let(:sam_handle) { double('sam_handle') }
    before :example do
      allow(described_class::SamrCloseHandleRequest).to receive(:new).and_return(samr_close_handle_request)
      allow(samr).to receive(:dcerpc_request).and_return(response)
      allow(described_class::SamrCloseHandleResponse).to receive(:read).and_return(samr_close_handle_response)
      allow(samr_close_handle_response).to receive_messages(
        :error_status => WindowsError::Win32::ERROR_SUCCESS,
        :sam_handle => sam_handle
      )
    end

    it 'sets the request with the expected values' do
      samr.close_handle(sam_handle)
      expect(described_class::SamrCloseHandleRequest).to have_received(:new).with(sam_handle: sam_handle)
    end
    it 'send the expected request structure' do
      samr.close_handle(sam_handle)
      expect(samr).to have_received(:dcerpc_request).with(samr_close_handle_request)
    end
    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::SamrCloseHandleResponse).to receive(:read).and_raise(IOError)
        expect { samr.close_handle(sam_handle) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(samr_close_handle_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { samr.close_handle(sam_handle) }.to raise_error(RubySMB::Dcerpc::Error::SamrError)
      end
    end
    it 'returns the expected handler' do
      expect(samr.close_handle(sam_handle)).to eq(sam_handle)
    end
    context 'with a real binary stream' do
      it 'returns the expected value' do
        raw_response = "\x00\x00\x00\x00\e\x05ucy\xE3\b@\xAC\xFDjc\xEB\xD1?\xBF\x00\x00\x00\x00"
        allow(samr).to receive(:dcerpc_request).and_return(raw_response)
        allow(described_class::SamrCloseHandleResponse).to receive(:read).and_call_original
        expect(samr.close_handle(sam_handle)).to eq({
          :context_handle_attributes=>0,
          :context_handle_uuid=>"6375051b-e379-4008-acfd-6a63ebd13fbf"
        })
      end
    end
  end
end
