RSpec.describe RubySMB::Dcerpc do
  let(:tree) { double('Tree') }
  let(:pipe) do
    RubySMB::SMB1::Pipe.new(
      tree: tree,
      response: RubySMB::SMB1::Packet::NtCreateAndxResponse.new,
      name: 'winreg'
    )
  end

  describe '#bind' do
    let(:options)         { { endpoint: RubySMB::Dcerpc::Winreg } }
    let(:bind_packet)     { RubySMB::Dcerpc::Bind.new(options) }
    let(:bind_ack_packet) { RubySMB::Dcerpc::BindAck.new }
    let(:client)          { double('Client') }

    before :example do
      allow(RubySMB::Dcerpc::Bind).to receive(:new).and_return(bind_packet)
      allow(pipe).to receive(:write)
      allow(pipe).to receive(:read)
      bind_ack_packet.p_result_list.n_results = 1
      bind_ack_packet.p_result_list.p_results[0].result = RubySMB::Dcerpc::BindAck::ACCEPTANCE
      allow(RubySMB::Dcerpc::BindAck).to receive(:read).and_return(bind_ack_packet)
      allow(tree).to receive(:client).and_return(client)
      allow(client).to receive(:max_buffer_size=)
      allow(client).to receive(:ntlm_client)
    end

    it 'creates a Bind packet' do
      pipe.bind(options)
      expect(RubySMB::Dcerpc::Bind).to have_received(:new).with(options)
    end

    it 'writes to the named pipe' do
      pipe.bind(options)
      expect(pipe).to have_received(:write).with(data: bind_packet.to_binary_s)
    end

    it 'reads the socket' do
      pipe.bind(options)
      expect(pipe).to have_received(:read)
    end

    it 'creates a BindAck packet from the response' do
      raw_response = RubySMB::Dcerpc::BindAck.new.to_binary_s
      allow(pipe).to receive(:read).and_return(raw_response)
      pipe.bind(options)
      expect(RubySMB::Dcerpc::BindAck).to have_received(:read).with(raw_response)
    end

    it 'raises the expected exception when an invalid packet is received' do
      allow(RubySMB::Dcerpc::BindAck).to receive(:read).and_raise(IOError)
      expect { pipe.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
    end

    it 'raises the expected exception when it is not a BindAck packet' do
      response = RubySMB::Dcerpc::Bind.new
      allow(RubySMB::Dcerpc::BindAck).to receive(:read).and_return(response)
      expect { pipe.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
    end

    it 'raises an exception when no result is returned' do
      bind_ack_packet.p_result_list.n_results = 0
      expect { pipe.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
    end

    it 'raises an exception when result is not ACCEPTANCE' do
      bind_ack_packet.p_result_list.p_results[0].result = RubySMB::Dcerpc::BindAck::USER_REJECTION
      expect { pipe.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
    end

    it 'sets the Tree #client.max_buffer_size property to the DCERPC response #max_xmit_frag property value' do
      bind_ack_packet.max_xmit_frag = 64
      pipe.bind(options)
      expect(client).to have_received(:max_buffer_size=).with(64)
    end

    it 'returns the expected BindAck packet' do
      expect(pipe.bind(options)).to eq(bind_ack_packet)
    end
  end
end
