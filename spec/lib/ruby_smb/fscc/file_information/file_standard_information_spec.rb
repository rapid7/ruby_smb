require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileStandardInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_STANDARD_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :allocation_size }
  it { should respond_to :end_of_file }
  it { should respond_to :number_of_links }
  it { should respond_to :delete_pending }
  it { should respond_to :directory }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the allocation size in a Int64 field' do
    expect(struct.allocation_size).to be_a BinData::Int64le
  end

  it 'tracks the file size in a Int64 field' do
    expect(struct.end_of_file).to be_a BinData::Int64le
  end

  it 'tracks the number of links in a Uint32 field' do
    expect(struct.number_of_links).to be_a BinData::Uint32le
  end

  it 'tracks if a delete is pending in a Int8 field' do
    expect(struct.delete_pending).to be_a BinData::Int8
  end

  it 'tracks if it is a directory in a Int8 field' do
    expect(struct.directory).to be_a BinData::Int8
  end

end
