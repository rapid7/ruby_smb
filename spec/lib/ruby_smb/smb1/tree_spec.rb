require 'spec_helper'

RSpec.describe RubySMB::SMB1::Tree do
  let(:ip) { '1.2.3.4' }
  let(:sock) { double('Socket', peeraddr: ip) }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }

  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:tree_id) { 2050 }
  let(:path) { "\\\\#{ip}\\example" }
  let(:response) {
    packet = RubySMB::SMB1::Packet::TreeConnectResponse.new
    packet.smb_header.tid = tree_id
    packet.parameter_block.access_rights.read("\xff\x01\x1f\x00")
    packet.parameter_block.guest_access_rights.read("\xff\x01\x1f\x01")
    packet
  }

  let(:disco_req) { RubySMB::SMB1::Packet::TreeDisconnectRequest.new }
  let(:disco_resp) { RubySMB::SMB1::Packet::TreeDisconnectResponse.new }

  subject(:tree) {
    described_class.new(client: client, share: path, response: response)
  }

  it { is_expected.to respond_to :client }
  it { is_expected.to respond_to :guest_permissions }
  it { is_expected.to respond_to :permissions }
  it { is_expected.to respond_to :share }
  it { is_expected.to respond_to :id }

  it 'inherits the client that spawned it' do
    expect(tree.client).to eq client
  end

  it 'inherits the guest permissions from the response packet' do
    expect(tree.guest_permissions).to eq response.parameter_block.guest_access_rights
  end

  it 'inherits the permissions from the response packet' do
    expect(tree.permissions).to eq response.parameter_block.access_rights
  end

  it 'inherits the Tree id from the response packet' do
    expect(tree.id).to eq response.smb_header.tid
  end

  describe '#disconnect!' do
    it 'calls #set_header_fields' do
      allow(RubySMB::SMB1::Packet::TreeDisconnectRequest).to receive(:new).and_return(disco_req)
      allow(client).to receive(:send_recv).and_return(disco_resp.to_binary_s)
      expect(tree).to receive(:set_header_fields).with(disco_req)
      tree.disconnect!
    end

    it 'sends a TreeDisconnectRequest with the Tree ID in the header' do
      allow(RubySMB::SMB1::Packet::TreeDisconnectRequest).to receive(:new).and_return(disco_req)
      modified_req = disco_req
      modified_req.smb_header.tid = tree.id
      expect(client).to receive(:send_recv).with(modified_req).and_return(disco_resp.to_binary_s)
      tree.disconnect!
    end

    it 'returns the NTStatus code from the response' do
      allow(client).to receive(:send_recv).and_return(disco_resp.to_binary_s)
      expect(tree.disconnect!).to eq disco_resp.status_code
    end
  end

  describe '#open_file' do
    let(:nt_create_andx_req)      { RubySMB::SMB1::Packet::NtCreateAndxRequest.new }
    let(:nt_create_andx_response) { RubySMB::SMB1::Packet::NtCreateAndxResponse.new }
    let(:filename) { "test_file\x00" }

    before :each do
      allow(RubySMB::SMB1::Packet::NtCreateAndxRequest).to receive(:new).and_return(nt_create_andx_req)
      allow(RubySMB::SMB1::Packet::NtCreateAndxResponse).to receive(:read).and_return(nt_create_andx_response)
    end

    it 'calls #set_header_fields' do
      allow(client).to receive(:send_recv).and_return(nt_create_andx_response.to_binary_s)
      expect(tree).to receive(:set_header_fields).with(nt_create_andx_req).and_call_original
      tree.open_file(filename: filename)
    end

    describe 'filename' do
      it 'takes the filename as an argument' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.data_block.file_name).to eq(filename)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'adds the null termination to the filename if missing' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.data_block.file_name).to eq(filename)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename.chop)
      end

      it 'adds the unicode null termination to the filename if Unicode is enabled' do
        unicode_filename = filename.encode('UTF-16LE')
        nt_create_andx_req.smb_header.flags2.unicode = 1
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.data_block.file_name).to eq(unicode_filename.b)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: unicode_filename.chop)
      end
    end

    describe 'flags' do
      it 'has the correct default fields set' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.flags.request_extended_response).to eq(1)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Flags as an argument' do
        flags = { request_extended_response: 0 }
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.flags.request_extended_response).to eq(0)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, flags: flags)
      end
    end

    describe 'options' do
      it 'has the correct default fields set' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.create_options.directory_file).to eq(0)
          expect(packet.parameter_block.create_options.non_directory_file).to eq(1)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Flags as an argument' do
        options = RubySMB::SMB1::BitField::CreateOptions.new(directory_file: 1)
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.create_options.directory_file).to eq(1)
          expect(packet.parameter_block.create_options.non_directory_file).to eq(0)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, options: options)
      end
    end

    describe 'disposition' do
      it 'defaults to FILE_OPEN' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.create_disposition).to eq(RubySMB::Dispositions::FILE_OPEN)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Disposition as an argument' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.create_disposition).to eq(RubySMB::Dispositions::FILE_OPEN_IF)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, disposition: RubySMB::Dispositions::FILE_OPEN_IF)
      end
    end

    describe 'impersonation level' do
      it 'defaults to SEC_IMPERSONATE' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.impersonation_level).to eq(RubySMB::ImpersonationLevels::SEC_IMPERSONATE)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Impersonation Level as an argument' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.impersonation_level).to eq(RubySMB::ImpersonationLevels::SEC_DELEGATE)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, impersonation: RubySMB::ImpersonationLevels::SEC_DELEGATE)
      end
    end

    describe 'RWD access permissions' do
      it 'will set the read permission from the parameters' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.share_access.share_read).to     eq(1)
          expect(packet.parameter_block.desired_access.read_data).to    eq(1)
          expect(packet.parameter_block.desired_access.read_ea).to      eq(1)
          expect(packet.parameter_block.desired_access.read_attr).to    eq(1)
          expect(packet.parameter_block.desired_access.read_control).to eq(1)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, read: true)
      end

      it 'will set the write permission from the parameters' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.share_access.share_write).to   eq(1)
          expect(packet.parameter_block.desired_access.write_data).to  eq(1)
          expect(packet.parameter_block.desired_access.append_data).to eq(1)
          expect(packet.parameter_block.desired_access.write_ea).to    eq(1)
          expect(packet.parameter_block.desired_access.write_attr).to  eq(1)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, write: true)
      end

      it 'will set the delete permission from the parameters' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.share_access.share_delete).to    eq(1)
          expect(packet.parameter_block.desired_access.delete_access).to eq(1)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, delete: true)
      end
    end

    it 'sends the NtCreateAndxRequest request packet and gets the expected NtCreateAndxResponse response back' do
      expect(client).to receive(:send_recv).with(nt_create_andx_req).and_return(nt_create_andx_response.to_binary_s)
      tree.open_file(filename: filename)
    end

    context 'when sending the request packet and gets a response back' do
      before :example do
        allow(client).to receive(:send_recv).with(nt_create_andx_req).and_return(nt_create_andx_response.to_binary_s)
      end

      it 'returns the expected RubySMB::SMB1::File object' do
        file_obj = RubySMB::SMB1::File.new(name: filename, tree: tree, response: nt_create_andx_response)
        expect(RubySMB::SMB1::File).to receive(:new).with(name: filename, tree: tree, response: nt_create_andx_response).and_return(file_obj)
        expect(tree.open_file(filename: filename)).to eq(file_obj)
      end

      context 'when the response is not a NtCreateAndxResponse packet' do
        it 'raise an InvalidPacket exception' do
          nt_create_andx_response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_ECHO
          expect { tree.open_file(filename: filename) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'when the response status code is not STATUS_SUCCESS' do
        it 'raise an UnexpectedStatusCode exception' do
          nt_create_andx_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
          expect { tree.open_file(filename: filename) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end
      end
    end
  end

  describe '#set_header_fields' do
    let(:modified_request) { tree.set_header_fields(disco_req) }
    it 'adds the TreeID to the header' do
      expect(modified_request.smb_header.tid).to eq tree.id
    end

    it 'sets the Flags2 extended attributes field to 1' do
      expect(modified_request.smb_header.flags2.eas).to eq 1
    end
  end

end
