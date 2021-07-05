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
    let(:response)        { double('NetShareEnumAllResponse') }
    let(:shares) do
      [
        RubySMB::Dcerpc::Srvsvc::ShareInfo1Element.new({:shi1_netname=>'C$', :shi1_type=>0, :shi1_remark=>'Default share'}),
        RubySMB::Dcerpc::Srvsvc::ShareInfo1Element.new({:shi1_netname=>'Shared', :shi1_type=>0, :shi1_remark=>''}),
        RubySMB::Dcerpc::Srvsvc::ShareInfo1Element.new({:shi1_netname=>'IPC$', :shi1_type=>2147483651, :shi1_remark=>'Remote IPC'}),
        RubySMB::Dcerpc::Srvsvc::ShareInfo1Element.new({:shi1_netname=>'ADMIN$', :shi1_type=>2147483648, :shi1_remark=>'Remote Admin'})
      ]
    end
    let(:result) do
      [
        {name: 'C$', type: 'DISK', comment: 'Default share'},
        {name: 'Shared', type: 'DISK', comment: ''},
        {name: 'IPC$', type: 'IPC|SPECIAL', comment: 'Remote IPC'},
        {name: 'ADMIN$', type: 'DISK|SPECIAL', comment: 'Remote Admin'}
      ]
    end

    before :example do
      allow(srvsvc).to receive(:bind)
      allow(RubySMB::Dcerpc::Srvsvc::NetShareEnumAllRequest).to receive(:new).and_return(request_packet)
      allow(srvsvc).to receive(:dcerpc_request).and_return(dcerpc_response)
      allow(RubySMB::Dcerpc::Srvsvc::NetShareEnumAllResponse).to receive(:read).and_return(response)
      allow(response).to receive_message_chain(:info_struct, :share_info, :buffer).and_return(shares)
    end

    it 'calls #bind with the expected arguments' do
      srvsvc.net_share_enum_all(host)
      expect(srvsvc).to have_received(:bind).with(endpoint: RubySMB::Dcerpc::Srvsvc)
    end

    it 'creates the expected NetShareEnumAllRequest packet' do
      srvsvc.net_share_enum_all(host)
      expect(RubySMB::Dcerpc::Srvsvc::NetShareEnumAllRequest).to have_received(:new).with(server_name: "\\\\#{host}")
    end

    it 'calls #request with the expected arguments' do
      srvsvc.net_share_enum_all(host)
      expect(srvsvc).to have_received(:dcerpc_request).with(request_packet)
    end

    it 'parse the response with NetShareEnumAllResponse' do
      srvsvc.net_share_enum_all(host)
      expect(RubySMB::Dcerpc::Srvsvc::NetShareEnumAllResponse).to have_received(:read).with(dcerpc_response)
    end

    it 'returns the remote shares' do
      expect(srvsvc.net_share_enum_all(host)).to eq(result)
    end
  end
end
