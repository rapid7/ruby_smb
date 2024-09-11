RSpec.describe RubySMB::Dcerpc::Wkssvc::WkssvcIdentifyHandle do
  subject(:packet) { described_class.new }

  it 'is a Ndr::NdrWideStringzPtr' do
    expect(packet).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringzPtr)
  end
end

RSpec.describe RubySMB::Dcerpc::Wkssvc do
  let(:wkssvc) do
    RubySMB::SMB1::Pipe.new(
      tree: double('Tree'),
      response: RubySMB::SMB1::Packet::NtCreateAndxResponse.new,
      name: 'wkssvc'
    )
  end

  describe '#netr_wksta_get_info' do
    let(:wkst_netr_wksta_get_info_request) { double('NetrWkstaGetInfoRequest') }
    let(:response) { double('Response') }
    let(:wkst_netr_wksta_get_info_response) { double('NetrWkstaGetInfoResponse') }
    let(:info) { double('info') }
    before :example do
      allow(described_class::NetrWkstaGetInfoRequest).to receive(:new).and_return(wkst_netr_wksta_get_info_request)
      allow(wkssvc).to receive(:dcerpc_request).and_return(response)
      allow(described_class::NetrWkstaGetInfoResponse).to receive(:read).and_return(wkst_netr_wksta_get_info_response)
      allow(wkst_netr_wksta_get_info_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_SUCCESS)
      allow(wkst_netr_wksta_get_info_response).to receive_message_chain(:wksta_info, :info => info)
    end

    it 'sets the request with the expected values' do
      wkssvc.netr_wksta_get_info
      expect(described_class::NetrWkstaGetInfoRequest).to have_received(:new).with(
        server_name: '',
        level: described_class::WKSTA_INFO_100
      )
    end
    it 'send the expected request structure' do
      wkssvc.netr_wksta_get_info
      expect(wkssvc).to have_received(:dcerpc_request).with(wkst_netr_wksta_get_info_request)
    end
    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::NetrWkstaGetInfoResponse).to receive(:read).and_raise(IOError)
        expect { wkssvc.netr_wksta_get_info }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(wkst_netr_wksta_get_info_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { wkssvc.netr_wksta_get_info }.to raise_error(RubySMB::Dcerpc::Error::WkssvcError)
      end
    end
    it 'returns the expected handler' do
      expect(wkssvc.netr_wksta_get_info).to eq(info)
    end
    context 'with a real binary stream' do
      it 'returns the expected value' do
        raw_response =
          "d\x00\x00\x00\x00\x00\x02\x00\xF4\x01\x00\x00\x04\x00\x02\x00\b"\
          "\x00\x02\x00\x06\x00\x00\x00\x02\x00\x00\x00\x0F\x00\x00\x00\x00"\
          "\x00\x00\x00\x0F\x00\x00\x00W\x00I\x00N\x00-\x00A\x00B\x00C\x00D"\
          "\x00E\x00F\x00C\x007\x006\x008\x00\x00\x00\x00\x00\x06\x00\x00"\
          "\x00\x00\x00\x00\x00\x06\x00\x00\x00M\x00Y\x00L\x00A\x00B\x00\x00"\
          "\x00\x00\x00\x00\x00"
        allow(wkssvc).to receive(:dcerpc_request).and_return(raw_response)
        allow(described_class::NetrWkstaGetInfoResponse).to receive(:read).and_call_original
        expect(wkssvc.netr_wksta_get_info).to eq({
          wki100_platform_id: 500,
          wki100_computername: "WIN-ABCDEFC768".encode('utf-16le'),
          wki100_langroup: "MYLAB".encode('utf-16le'),
          wki100_ver_major: 6,
          wki100_ver_minor: 2
        })
      end
    end
  end

  describe '#netr_wksta_user_enum' do
    let(:wkst_netr_wksta_user_enum_request) { double('NetrWkstaUserEnumRequest') }
    let(:response) { double('Response') }
    let(:wkst_netr_wksta_user_enum_response) { double('NetrWkstaUserEnumResponse') }
    let(:info) { double('info') }
    before :example do
      allow(described_class::NetrWkstaUserEnumRequest).to receive(:new).and_return(wkst_netr_wksta_user_enum_request)
      allow(wkssvc).to receive(:dcerpc_request).and_return(response)
      allow(described_class::NetrWkstaUserEnumResponse).to receive(:read).and_return(wkst_netr_wksta_user_enum_response)
      allow(wkst_netr_wksta_user_enum_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_SUCCESS)
      allow(wkst_netr_wksta_user_enum_response).to receive_message_chain(:user_info, :info => info)
    end

    it 'sets the request with the expected values' do
      wkssvc.netr_wksta_user_enum
      expect(described_class::NetrWkstaUserEnumRequest).to have_received(:new).with(
        server_name: '',
        user_info: {
          level: described_class::WKSTA_USER_INFO_0,
          tag: described_class::WKSTA_USER_INFO_0,
          info: {
            wkui0_entries_read: 0,
          },
        },
        preferred_max_length: 0xFFFFFFFF,
        result_handle: 0
      )
    end
    it 'send the expected request structure' do
      wkssvc.netr_wksta_user_enum
      expect(wkssvc).to have_received(:dcerpc_request).with(wkst_netr_wksta_user_enum_request)
    end
    context 'when an IOError occurs while parsing the response' do
      it 'raises a RubySMB::Dcerpc::Error::InvalidPacket' do
        allow(described_class::NetrWkstaUserEnumResponse).to receive(:read).and_raise(IOError)
        expect { wkssvc.netr_wksta_user_enum }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response error status is not WindowsError::Win32::ERROR_SUCCESS' do
      it 'raises a RubySMB::Dcerpc::Error::WinregError' do
        allow(wkst_netr_wksta_user_enum_response).to receive(:error_status).and_return(WindowsError::Win32::ERROR_INVALID_DATA)
        expect { wkssvc.netr_wksta_user_enum }.to raise_error(RubySMB::Dcerpc::Error::WkssvcError)
      end
    end
    it 'returns the expected handler' do
      expect(wkssvc.netr_wksta_user_enum).to eq(info)
    end
  end
end
