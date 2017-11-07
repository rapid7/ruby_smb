require 'spec_helper'

RSpec.describe RubySMB::Dcerpc::Srvsvc do
  let(:srvsvc_stub) {RubySMB::Dcerpc::Srvsvc::NetShareEnumAll.new}
  let(:server_unc) { '127.0.0.1' }

  describe '#initialize' do
    it 'it is 8-octet aligned' do
      expect(srvsvc_stub.do_num_bytes % 8).to eq 0
    end
  end

end
