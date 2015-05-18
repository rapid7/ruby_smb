require 'smb2'

RSpec.describe Smb2::Packet do
  let(:klass) do
    Class.new(described_class) do
      nest :header, Smb2::Packet::RequestHeader
      # struct_size is part of the API and must be present
      # 2 bytes for struct_size itself, 2 for data_offset, 4 for data_length
      unsigned :struct_size, 16, default: 2 + 2 + 4
      data_buffer :data, 32
      rest :buffer
    end
  end

  subject(:packet) do
    klass.new
  end

  it { is_expected.to respond_to(:data) }
  it { is_expected.to respond_to(:data_length) }
  it { is_expected.to respond_to(:data_offset) }
  it { is_expected.to respond_to(:recalculate) }
  it { is_expected.to_not respond_to(:data_padding) }

  context 'with padding' do

    let(:klass) do
      Class.new(described_class) do
        nest :header, Smb2::Packet::RequestHeader
        # same as above, +1 for padding byte
        unsigned :struct_size, 16, default: 2 + 2 + 4 + 1
        data_buffer :data, 32, padding: 8
        rest :buffer
      end
    end

    it { is_expected.to respond_to(:data) }
    it { is_expected.to respond_to(:data_length) }
    it { is_expected.to respond_to(:data_offset) }
    it { is_expected.to respond_to(:data_padding) }
    it { is_expected.to respond_to(:recalculate) }

  end

  describe '#initialize' do
    subject { klass }

    context 'without block' do

      specify do
        inst = nil
        expect {
          inst = klass.new(data: "asdf")
        }.to_not raise_error
        expect(inst.struct_size).to eq(8)
        expect(inst.data_length).to eq(4)
        expect(inst.data).to eq("asdf")
      end

    end

    context 'with block' do

      specify do
        inst = nil
        expect {
          inst = klass.new do |packet|
            packet.data = "asdf"
          end
        }.to_not raise_error
        expect(inst.struct_size).to eq(8)
        expect(inst.data_length).to eq(4)
        expect(inst.data).to eq("asdf")
      end

    end

  end

  describe '#data_buffer_fields' do
    specify do
      expect(packet.data_buffer_fields).to eq([:data])
    end
  end

  describe '#<data buffer>=' do
    specify do
      expect(packet).to receive(:recalculate).once.and_call_original
      expect { packet.data = 'asdf' }.not_to raise_error
      expect(packet.data).to eq('asdf')
    end
  end

  describe '#recalculate' do

    context 'with utf-16le field' do
      let(:value) { "omg data".encode("utf-16le") }
      before do
        packet.data = value
      end

      specify do
        # length of header (64) +
        # length of struct_size (2) +
        # length of data offset (2) +
        # length data length (4)
        expect(packet.data_offset).to eq(64 + 2 + 2 + 4)
      end

      specify do
        expect(packet.data_length).to eq(value.bytesize)
      end

      specify do
        expect(packet.data).to eq(value.force_encoding("binary"))
      end

    end

    context 'with ascii-8bit field' do
      let(:value) { "omg data".encode("ascii-8bit") }
      before do
        packet.data = value
      end

      specify do
        # length of header (64) +
        # length of struct_size (2) +
        # length of data offset (2) +
        # length data length (4)
        expect(packet.data_offset).to eq(64 + 2 + 2 + 4)
      end

      specify do
        expect(packet.data_length).to eq(value.bytesize)
      end

      specify do
        expect(packet.data).to eq(value.force_encoding("binary"))
      end

    end
  end
end
