require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileInternalInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_INTERNAL_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :file_id }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the file ID in a Uint64 field' do
    expect(struct.file_id).to be_a BinData::Uint64le
  end

end
