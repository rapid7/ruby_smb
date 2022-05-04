require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileModeInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_MODE_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :flags }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the flags in a struct field' do
    expect(struct.flags).to be_a BinData::Struct
  end

end
