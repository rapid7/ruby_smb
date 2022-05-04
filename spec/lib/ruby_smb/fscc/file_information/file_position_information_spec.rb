require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FilePositionInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_POSITION_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :current_byte_offset }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the current byte offset in a Int64 field' do
    expect(struct.current_byte_offset).to be_a BinData::Int64le
  end

end
