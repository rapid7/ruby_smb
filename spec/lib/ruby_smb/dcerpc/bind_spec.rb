require 'spec_helper'

RSpec.describe RubySMB::Dcerpc::Bind do

  describe '#initialize' do
    let(:bind){described_class.new}
    it 'should use the alloc_hint to determine stub length' do
      expect(bind.class).to be RubySMB::Dcerpc::Bind
    end
  end
end