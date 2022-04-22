require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileStreamInformation do
  it 'references the correct class level' do
    expect(described_class).to be_const_defined(:CLASS_LEVEL)
    expect(described_class::CLASS_LEVEL).to be RubySMB::Fscc::FileInformation::FILE_STREAM_INFORMATION
  end

  subject(:struct) { described_class.new }

  it { should respond_to :next_entry_offset }
  it { should respond_to :stream_name_length }
  it { should respond_to :stream_size }
  it { should respond_to :stream_allocation_size }
  it { should respond_to :stream_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the next entry offset in a Uint32 field' do
    expect(struct.next_entry_offset).to be_a BinData::Uint32le
  end

  it 'tracks the stream name length in a Uint32 field' do
    expect(struct.stream_name_length).to be_a BinData::Uint32le
  end

  it 'tracks the stream size in a Int64 field' do
    expect(struct.stream_size).to be_a BinData::Int64le
  end

  it 'tracks the stream allocation size in a Int64 field' do
    expect(struct.stream_allocation_size).to be_a BinData::Int64le
  end

  it 'tracks the stream name in a String16 field' do
    expect(struct.stream_name).to be_a RubySMB::Field::String16
  end

  it 'tracks the length of the stream_name field' do
    struct.stream_name = 'Hello.txt'
    expect(struct.stream_name_length).to eq struct.stream_name.do_num_bytes
  end

  it 'automatically encodes the stream name in UTF-16LE' do
    name = 'Hello_world.txt'
    struct.stream_name = name
    expect(struct.stream_name.force_encoding('utf-16le')).to eq name.encode('utf-16le')
  end
end
