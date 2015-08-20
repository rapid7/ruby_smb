require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::NegotiateCommand::Dialect do

  subject(:dialect) { described_class.new }

  it { is_expected.to respond_to :buffer_format }
  it { is_expected.to respond_to :dialect_string }

  describe 'buffer_format' do
    it 'should be an 8-bit field per the SMB spec' do
      expect(dialect.buffer_format.num_bytes).to eq 1
    end

    it 'should default to 0x2' do
      expect(dialect.buffer_format).to eq 0x2
    end
  end

  describe 'dialect_string' do
    it 'should add a null terminator to the end of the dialect string' do
      dialect.dialect_string = 'NT LM 0.12'
      expect(dialect.dialect_string.num_bytes).to eq 11
    end

    it 'raises a BinData::ValidityError if dialect_string is not a supported dialect' do
      expect{ dialect.dialect_string = 'foo'}.
        to raise_error BinData::ValidityError, "value 'foo' not as expected for obj.dialect_string"
    end
  end
end