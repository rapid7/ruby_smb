require 'spec_helper'

RSpec.describe RubySMB::Dcerpc::Handle do

  describe 'A dce/rpc handle' do
    let(:output){double('Output')}
    let(:tree){double('Tree')}
    let(:response){double('Response')}
    let(:file){double('File')}
    let(:handle){described_class.new(file)}
    let(:endpoint){ RubySMB::Dcerpc::Srvsvc }
    let(:ioctl_response){ double('IoctlResponse') }

    it 'should #bind' do
      expect(handle).to receive(:ioctl_request)#.with([response_socket], nil, nil, timeout)
      handle.bind(endpoint: endpoint)
    end

    it 'should #request' do
      expect(handle).to receive(:ioctl_request)#.with([response_socket], nil, nil, timeout)
      handle.request(opnum: 15, stub: RubySMB::Dcerpc::Srvsvc::NetShareEnumAll, options: {host: '127.0.0.1'})
    end

    it 'should #handle_msg' do
      expect(ioctl_response).to receive(:buffer).and_return RubySMB::Dcerpc::Response.new.stub
      expect(RubySMB::Dcerpc::PduHeader).to receive(:read).and_return(RubySMB::Dcerpc::PduHeader.new(ptype: 1))
      expect(handle.handle_msg(ioctl_response)).to eq(RubySMB::Dcerpc::Response.new.stub.to_binary_s)
    end
  end
  
end