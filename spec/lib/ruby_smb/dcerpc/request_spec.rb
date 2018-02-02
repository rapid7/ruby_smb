require 'spec_helper'

RSpec.describe RubySMB::Dcerpc::Request do

  describe 'when making a NetShareEnumAll dcerpc request' do
    let(:request){
      described_class.new(
          opnum: RubySMB::Dcerpc::Srvsvc::NetShareEnumAll::Opnum,
          stub: RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.new(host: '192.161.204.122').to_binary_s
      )
    }

    it 'should create a Request struct with NetShareEnumAll as stub with size of 106' do
      expect(request.do_num_bytes).to eq 106
    end

    it 'should set the correct opnum' do
      expect(request.opnum).to eq 0xF
    end
  end
end
