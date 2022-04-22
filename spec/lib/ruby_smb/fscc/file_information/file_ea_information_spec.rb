require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileEaInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_EA_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :ea_size }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the extended attributes size in a Uint32 field' do
    expect(struct.ea_size).to be_a BinData::Uint32le
  end

end
