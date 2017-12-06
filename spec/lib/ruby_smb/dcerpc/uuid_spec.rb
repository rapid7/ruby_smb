require 'spec_helper'

RSpec.describe RubySMB::Dcerpc::Uuid do
  let(:uuid_string){'8a885d04-1ceb-11c9-9fe8-08002b104860'}
  let(:uuid){RubySMB::Dcerpc::Uuid.new(initial_value: uuid_string)}

  describe '#initialize' do
    it 'should create a 16 byte struct' do
      expect(uuid.do_num_bytes).to be 16
    end
  end
end