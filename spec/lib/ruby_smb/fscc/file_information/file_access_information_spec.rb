require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileAccessInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_ACCESS_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :access_flags }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the access flags in a Uint32 field' do
    expect(struct.access_flags).to be_a BinData::Uint32le
  end

end
