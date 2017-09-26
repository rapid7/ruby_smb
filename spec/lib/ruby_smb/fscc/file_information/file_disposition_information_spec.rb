require 'spec_helper'

RSpec.describe RubySMB::Fscc::FileInformation::FileDispositionInformation do
  subject(:struct) { described_class.new }

  it { should respond_to :buffer_length }
  it { should respond_to :buffer_offset }
  it { should respond_to :buffer }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
end
