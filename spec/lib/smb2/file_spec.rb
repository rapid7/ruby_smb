
RSpec.describe Smb2::File do
  subject(:file) do
    described_class.new(tree: tree, create_response: create_response)
  end

  let(:create_response) do
    cr = double('Smb2::Packet::CreateResponse')
    allow(cr).to receive(:file_id) { "f"*16 }
    cr
  end

  let(:real_file_size) { data.length }

  let(:max_read_size) { 10 }

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
      let(:data) { "A" * (max_read_size + 1) }

      specify do
        expect(tree).to receive(:send_recv).twice.with(instance_of(Smb2::Packet::ReadRequest))
        expect(file.read).to eq(data)
      end

      context 'with an offset that makes it less than max read size' do

        specify do
          expect(tree).to receive(:send_recv).once.with(instance_of(Smb2::Packet::ReadRequest))
          offset = (data.length - max_read_size/2)
          expect(file.read(offset: offset)).to eq(data.slice(offset .. data.length))
        end

      end
    end
  end

end
