require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileAlignmentInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_ALIGNMENT_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :alignment_requirement }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the alignment requirement in a Uint32 field' do
    expect(struct.alignment_requirement).to be_a BinData::Uint32le
  end

end
