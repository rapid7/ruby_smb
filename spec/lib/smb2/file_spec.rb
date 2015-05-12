
RSpec.describe Smb2::File do
  subject(:file) do
    described_class.new(filename: "test.txt", tree: tree, create_response: create_response)
  end

  let(:create_response) do
    cr = double('Smb2::Packet::CreateResponse')
    allow(cr).to receive(:file_id) { "f"*16 }
    cr
  end

  let(:real_file_size) { data.length }

  let(:max_read_size) { 10 }

  let(:max_write_size) { 10 }

  context '#read' do
    let(:tree) do
      t = double('Smb2::Tree')
      allow(t).to receive_message_chain(:client, :max_read_size) { max_read_size }
      allow(t).to receive(:send_recv) do |packet|
        Smb2::Packet::ReadResponse.new do |response|
          response.data = data.slice(packet.read_offset, packet.read_length)
        end
      end
      t
    end

    before do
      allow(file).to receive(:size).and_return(real_file_size)
    end

    context 'with data smaller than max read size' do
      let(:data) { "A" * (max_read_size - 1) }
      specify do
        expect(tree).to receive(:send_recv).once.with(instance_of(Smb2::Packet::ReadRequest))
        expect(file.read).to eq(data)
      end
    end

    context 'with data equal to max read size' do
      let(:data) { "A" * (max_read_size) }
      specify do
        expect(tree).to receive(:send_recv).once.with(instance_of(Smb2::Packet::ReadRequest))
        expect(file.read).to eq(data)
      end
    end

    context 'with data bigger than max read size' do
      let(:data) { "A"*max_read_size + "B"*max_read_size + "C" }

      specify do
        expect(tree).to receive(:send_recv)
          .exactly(1 + (data.length / max_read_size)).times
          .with(instance_of(Smb2::Packet::ReadRequest))
        expect(file.read).to eq(data)
      end

      context 'with an offset that makes it less than max read size' do
        specify do
          expect(tree).to receive(:send_recv).once.with(instance_of(Smb2::Packet::ReadRequest))
          offset = (data.length - max_read_size/2)
          file.seek(offset)
          expect(file.read).to eq(data.slice(offset .. data.length))
        end
      end

      context 'with an offset in the middle and length less than max_read_size' do
        specify do
          expect(tree).to receive(:send_recv).once.with(instance_of(Smb2::Packet::ReadRequest))
          offset = (data.length/2 - max_read_size/2)
          file.seek(offset)
          length = max_read_size - 1
          expect(file.read(length)).to eq(data.slice(offset, length))
        end
      end

    end

  end

  context '#write' do
    let(:tree) do
      t = double('Smb2::Tree')
      allow(t).to receive_message_chain(:client, :max_write_size) { max_write_size }
      t
    end

    context 'with data larger than max_write_size' do

      let(:data) { "A" * max_write_size * 2 }

      specify do
        expected_len = data.length / 2
        response_packet = Smb2::Packet::WriteResponse.new(byte_count: expected_len)

        expect(file).to receive(:write_chunk).
          once.with(data[0, expected_len], offset: 0).
          and_return(response_packet)
        expect(file).to receive(:write_chunk).
          once.with(data[expected_len .. -1], offset: expected_len).
          and_return(response_packet)

        file.write(data)
      end

    end

  end

  context '#write_chunk' do
    let(:tree) do
      t = double('Smb2::Tree')
      allow(t).to receive_message_chain(:client, :max_write_size) { max_write_size }
      allow(t).to receive(:send_recv) do |packet|
        response = Smb2::Packet::WriteResponse.new(
          byte_count: [ packet.data_length, max_write_size ].min
        )
        header = response.header
        header.nt_status = 0
        response.header = header

        response
      end
      t
    end

    let(:data) { "asdf" }

    context 'with less data than max_write_size' do
      let(:max_write_size) do
        data.length + 1
      end

      specify do
        expect(tree).to receive(:send_recv).once.with(instance_of(Smb2::Packet::WriteRequest))
        expect(file.write_chunk(data)).to be_a(Smb2::Packet::WriteResponse)
      end

      specify do
        expect(tree).to receive(:send_recv).once.with(instance_of(Smb2::Packet::WriteRequest))
        packet = file.write_chunk(data)
        expect(packet).to be_a(Smb2::Packet::WriteResponse)
        expect(packet.byte_count).to eq(data.length)
      end

    end

  end

end
