RSpec.describe RubySMB::Dcerpc::Srvsvc do
  let(:srvsvc) do
    RubySMB::SMB1::Pipe.new(
      tree: double('Tree'),
      response: RubySMB::SMB1::Packet::NtCreateAndxResponse.new,
      name: 'srvsvc'
    )
  end

  describe '#net_share_enum_all' do
    let(:host)            { '1.2.3.4' }
    let(:request_packet)  { double('NetShareEnumAll request packet') }
    let(:dcerpc_response) { double('DCERPC response') }
    let(:shares) do
      [
        ["C$", "DISK", "Default share"],
        ["Shared", "DISK", ""],
        ["IPC$", "IPC", "Remote IPC"],
        ["ADMIN$", "DISK", "Remote Admin"]
      ]
    end

    before :example do
      allow(srvsvc).to receive(:bind)
      allow(RubySMB::Dcerpc::Srvsvc::NetShareEnumAll).to receive(:new).and_return(request_packet)
      allow(srvsvc).to receive(:dcerpc_request).and_return(dcerpc_response)
      allow(RubySMB::Dcerpc::Srvsvc::NetShareEnumAll).to receive(:parse_response).and_return(shares)
    end

    it 'calls #bind with the expected arguments' do
      srvsvc.net_share_enum_all(host)
      expect(srvsvc).to have_received(:bind).with(endpoint: RubySMB::Dcerpc::Srvsvc)
    end

    it 'creates the expected NetShareEnumAll packet' do
      srvsvc.net_share_enum_all(host)
      expect(RubySMB::Dcerpc::Srvsvc::NetShareEnumAll).to have_received(:new).with(host: host)
    end

    it 'calls #request with the expected arguments' do
      srvsvc.net_share_enum_all(host)
      expect(srvsvc).to have_received(:dcerpc_request).with(request_packet)
    end

    it 'parse the response with NetShareEnumAll #parse_response method' do
      srvsvc.net_share_enum_all(host)
      expect(RubySMB::Dcerpc::Srvsvc::NetShareEnumAll).to have_received(:parse_response).with(dcerpc_response)
    end

    it 'returns the remote shares' do
      output = [
        {:name=>"C$", :type=>"DISK", :comment=>"Default share"},
        {:name=>"Shared", :type=>"DISK", :comment=>""},
        {:name=>"IPC$", :type=>"IPC", :comment=>"Remote IPC"},
        {:name=>"ADMIN$", :type=>"DISK", :comment=>"Remote Admin"},
      ]
      expect(srvsvc.net_share_enum_all(host)).to eq(output)
    end
  end
end
