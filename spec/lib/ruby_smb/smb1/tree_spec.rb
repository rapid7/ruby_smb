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
    let(:disco_response) { double('Response') }

    before :example do
      allow(RubySMB::SMB1::Packet::TreeDisconnectRequest).to receive(:new).and_return(disco_req)
      allow(RubySMB::SMB1::Packet::TreeDisconnectResponse).to receive(:read).and_return(disco_resp)
      allow(client).to receive(:send_recv)
    end

    it 'calls #set_header_fields' do
      expect(tree).to receive(:set_header_fields).with(disco_req)
      tree.disconnect!
    end

    it 'sends a TreeDisconnectRequest with the Tree ID in the header' do
      modified_req = disco_req
      modified_req.smb_header.tid = tree.id
      expect(client).to receive(:send_recv).with(modified_req)
      tree.disconnect!
    end

    it 'returns the NTStatus code from the response' do
      expect(tree.disconnect!).to eq disco_resp.status_code
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(disco_resp).to receive(:valid?).and_return(false)
      expect { tree.disconnect! }.to raise_error(RubySMB::Error::InvalidPacket)
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
          expect(packet.data_block.file_name.to_binary_s).to eq(filename)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'adds the null termination to the filename if missing' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.data_block.file_name.to_binary_s).to eq(filename)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename.chop)
      end

      it 'adds the unicode null termination to the filename if Unicode is enabled' do
        unicode_filename = filename.encode('UTF-16LE')
        nt_create_andx_req.smb_header.flags2.unicode = 1
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.data_block.file_name.to_binary_s).to eq(unicode_filename.b)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: unicode_filename.chop)
      end

      it 'removes the leading \\ from the filename if needed' do
        expect(tree).to receive(:_open).with(filename: filename)
        tree.open_file(filename: '\\' + filename)
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
        it 'raises an InvalidPacket exception' do
          nt_create_andx_response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_ECHO
          expect { tree.open_file(filename: filename) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'when the response status code is not STATUS_SUCCESS' do
        it 'raises an UnexpectedStatusCode exception' do
          nt_create_andx_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
          expect { tree.open_file(filename: filename) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end
      end
    end
  end

  describe '#list' do
    let(:find_first2_req) { RubySMB::SMB1::Packet::Trans2::FindFirst2Request.new }
    let(:file_info1) do
      file_info = RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo.new
      file_info.unicode = true
      file_info.file_name = 'test1.txt'
      file_info
    end
    let(:find_first2_res) do
      packet = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.new
      packet.data_block.trans2_parameters.eos = 1
      packet.data_block.trans2_data.buffer = file_info1.to_binary_s
      packet
    end

    before :each do
      allow(RubySMB::SMB1::Packet::Trans2::FindFirst2Request).to receive(:new).and_return(find_first2_req)
      allow(client).to receive(:send_recv)
      allow(RubySMB::SMB1::Packet::Trans2::FindFirst2Response).to receive(:read).and_return(find_first2_res)
    end

    it 'calls #set_header_fields' do
      expect(tree).to receive(:set_header_fields).with(find_first2_req).and_call_original
      tree.list
    end

    it 'sets the unicode flag when the unicode argument is true (default)' do
      allow(client).to receive(:send_recv).with(find_first2_req) do |packet|
        expect(packet.smb_header.flags2.unicode).to eq 1
      end
      tree.list
    end

    it 'does not set the unicode flag when the unicode argument is false' do
      allow(client).to receive(:send_recv).with(find_first2_req) do |packet|
        expect(packet.smb_header.flags2.unicode).to eq 0
      end
      tree.list(unicode: false)
    end

    it 'adds a leading and trailing \\ to the search path if not present' do
      directory = 'dir'
      search = ('\\' + directory + '\\*').encode('UTF-16LE')
      allow(client).to receive(:send_recv).with(find_first2_req) do |packet|
        expect(packet.data_block.trans2_parameters.filename).to eq search
      end
      tree.list(directory: directory)
    end

    it 'sets the expected default search parameters' do
      allow(client).to receive(:send_recv).with(find_first2_req) do |packet|
        t2_params = packet.data_block.trans2_parameters
        expect(t2_params.search_attributes.hidden).to eq 1
        expect(t2_params.search_attributes.system).to eq 1
        expect(t2_params.search_attributes.directory).to eq 1
        expect(t2_params.flags.close_eos).to eq 1
        expect(t2_params.flags.resume_keys).to eq 0
        expect(t2_params.information_level).to eq RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo::CLASS_LEVEL
        expect(t2_params.filename).to eq '\\*'.encode('UTF-16LE')
        expect(t2_params.search_count).to eq 10
      end
      tree.list
    end

    it 'calls #set_find_params' do
      expect(tree).to receive(:set_find_params).with(find_first2_req).and_call_original
      tree.list
    end

    it 'calls FindFileFullDirectoryInfo#results' do
      expect(find_first2_res).to receive(:results).with(RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo, unicode: true).and_call_original
      tree.list
    end

    it 'returns the expected FindFileFullDirectoryInfo structure' do
      expect(tree.list).to eq([file_info1])
    end

    it 'returns the expected FindFileFullDirectoryInfo structures when multiple files are listed' do
      file_info1.next_offset = file_info1.do_num_bytes
      file_info2 = RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo.new
      file_info2.unicode = true
      file_info2.file_name = 'test2.txt'
      find_first2_res.data_block.trans2_data.buffer = file_info1.to_binary_s + file_info2.to_binary_s

      expect(tree.list).to eq([file_info1, file_info2])
    end

    context 'when the response is not a valid Trans2 FindFirst2Response' do
      it 'raises an InvalidPacket exception' do
        find_first2_res.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_ECHO
        expect { tree.list }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    context 'when the response status code is not STATUS_SUCCESS' do
      it 'raises an UnexpectedStatusCode exception' do
        find_first2_res.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
        expect { tree.list }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
      end
    end

    context 'when more requests are needed to get all the information' do
      let(:find_next2_req) { RubySMB::SMB1::Packet::Trans2::FindNext2Request.new }
      let(:file_info2) do
        file_info = RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo.new
        file_info.unicode = true
        file_info.file_name = 'test2.txt'
        file_info
      end
      let(:find_next2_res) do
        packet = RubySMB::SMB1::Packet::Trans2::FindNext2Response.new
        packet.data_block.trans2_parameters.eos = 1
        packet.data_block.trans2_data.buffer = file_info2.to_binary_s
        packet
      end
      let(:sid) { 0x1000 }

      before :each do
        find_first2_res.data_block.trans2_parameters.eos = 0
        find_first2_res.data_block.trans2_parameters.sid = sid
        allow(RubySMB::SMB1::Packet::Trans2::FindNext2Request).to receive(:new).and_return(find_next2_req)
        allow(client).to receive(:send_recv).with(find_next2_req)
        allow(RubySMB::SMB1::Packet::Trans2::FindNext2Response).to receive(:read).and_return(find_next2_res)
      end

      it 'calls #set_header_fields' do
        expect(tree).to receive(:set_header_fields).with(find_first2_req).once.ordered.and_call_original
        expect(tree).to receive(:set_header_fields).with(find_next2_req).once.ordered.and_call_original
        tree.list
      end

      it 'sets the unicode flag when the unicode argument is true (default)' do
        allow(client).to receive(:send_recv).with(find_next2_req) do |packet|
          expect(packet.smb_header.flags2.unicode).to eq 1
        end
        tree.list
      end

      it 'does not set the unicode flag when the unicode argument is false' do
        allow(client).to receive(:send_recv).with(find_next2_req) do |packet|
          expect(packet.smb_header.flags2.unicode).to eq 0
        end
        tree.list(unicode: false)
      end

      it 'sets the expected default search parameters' do
        allow(client).to receive(:send_recv).with(find_next2_req) do |packet|
          t2_params = packet.data_block.trans2_parameters
          expect(t2_params.sid).to eq sid
          expect(t2_params.flags.close_eos).to eq 1
          expect(t2_params.flags.resume_keys).to eq 0
          expect(t2_params.information_level).to eq RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo::CLASS_LEVEL
          expect(t2_params.filename).to eq file_info1.file_name
          expect(t2_params.search_count).to eq 10
        end
        tree.list
      end

      it 'calls #set_find_params' do
        expect(tree).to receive(:set_find_params).with(find_first2_req).once.ordered.and_call_original
        expect(tree).to receive(:set_find_params).with(find_next2_req).once.ordered.and_call_original
        tree.list
      end

      it 'calls FindFileFullDirectoryInfo#results' do
        expect(find_first2_res).to receive(:results).with(RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo, unicode: true).once.ordered.and_call_original
        expect(find_next2_res).to receive(:results).with(RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo, unicode: true).once.ordered.and_call_original
        tree.list
      end

      it 'returns the expected FindFileFullDirectoryInfo structures' do
        expect(tree.list).to eq([file_info1, file_info2])
      end

      context 'when the response is not a valid Trans2 FindNext2Response' do
        it 'raises an InvalidPacket exception' do
          find_next2_res.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_ECHO
          expect { tree.list }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'when the response status code is not STATUS_SUCCESS' do
        it 'raises an UnexpectedStatusCode exception' do
          find_next2_res.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
          expect { tree.list }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end
      end
    end

    context 'with SMB_INFO_STANDARD (LANMAN 2.0 / Win9x)' do
      let(:info_standard) { RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindInfoStandard }

      def build_info_standard_entry(name:, size: 0, attrs: 0x20, pad_after: false)
        entry = info_standard.new
        entry.data_size = size
        entry.allocation_size = size
        entry.file_attributes = attrs
        entry.file_name = name
        entry.file_name_length = name.bytesize
        pad_after ? entry.to_binary_s + "\x00" : entry.to_binary_s
      end

      def build_find_first2_raw(blob, status: 0)
        packet = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.new
        packet.smb_header.nt_status = status
        packet.data_block.trans2_parameters.eos = 1
        packet.data_block.trans2_data.buffer = blob
        packet.to_binary_s
      end

      before :each do
        # Undo the default FindFirst2Response stubs from the outer #list block
        allow(RubySMB::SMB1::Packet::Trans2::FindFirst2Request).to receive(:new).and_call_original
        allow(RubySMB::SMB1::Packet::Trans2::FindFirst2Response).to receive(:read).and_call_original
      end

      it 'parses sequential SMB_INFO_STANDARD entries separated by a null pad' do
        # Win9x servers insert a trailing null byte between entries.
        blob = build_info_standard_entry(name: 'foo.txt', size: 100, pad_after: true) +
               build_info_standard_entry(name: 'barbaz', size: 200)
        allow(client).to receive(:send_recv).and_return(build_find_first2_raw(blob))

        results = tree.list(type: info_standard)

        expect(results.length).to eq 2
        expect(results[0].file_name).to eq 'foo.txt'
        expect(results[0].data_size).to eq 100
        expect(results[1].file_name).to eq 'barbaz'
        expect(results[1].data_size).to eq 200
      end

      it 'parses a single SMB_INFO_STANDARD entry without trailing padding' do
        blob = build_info_standard_entry(name: 'only.txt', size: 42)
        allow(client).to receive(:send_recv).and_return(build_find_first2_raw(blob))

        results = tree.list(type: info_standard)

        expect(results.length).to eq 1
        expect(results[0].file_name).to eq 'only.txt'
        expect(results[0].data_size).to eq 42
      end

      it 'stops when an entry has a zero file_name_length' do
        entry = build_info_standard_entry(name: 'first.txt', pad_after: true)
        zero  = "\x00" * 23
        blob  = entry + zero
        allow(client).to receive(:send_recv).and_return(build_find_first2_raw(blob))

        results = tree.list(type: info_standard)

        expect(results.map(&:file_name)).to eq(['first.txt'])
      end

      it 'raises UnexpectedStatusCode when the SMB status is not success' do
        allow(client).to receive(:send_recv).and_return(
          build_find_first2_raw('', status: WindowsError::NTStatus::STATUS_ACCESS_DENIED.value)
        )
        expect { tree.list(type: info_standard) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
      end

      it 'turns unicode off and raises search_count to 255 for SMB_INFO_STANDARD' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.smb_header.flags2.unicode).to eq 0
          expect(packet.data_block.trans2_parameters.search_count).to eq 255
          build_find_first2_raw('')
        end
        tree.list(type: info_standard)
      end

      it 'returns an empty array when the data blob is empty' do
        allow(client).to receive(:send_recv).and_return(build_find_first2_raw(''))
        expect(tree.list(type: info_standard)).to eq([])
      end

      context 'against a Win9x-era server that omits the trans2 4-byte alignment pad' do
        # Wire layout: word_count=10 (no setup section), parameter_offset=55
        # points right after byte_count (no pad1), data_offset=66 points after
        # trans2_parameters + 1-byte pad2. BinData's Trans2::DataBlock inserts
        # its usual pad1 on read, so trans2_data.buffer arrives (data_count -
        # pad1_length) bytes short and #results would otherwise see 0 entries.
        # The Tree#list workaround detects the mismatch and re-slices the
        # buffer from the server-reported data_offset.
        def build_win9x_find_first2_raw
          data_count       = 87
          parameter_offset = 55
          data_offset      = 66
          smb_header  = "\xffSMB\x32".b + "\x00".b * 4 + "\x98".b + "\x03\x60".b + ("\x00".b * 20)
          param_block = [10, data_count, 0, 10, parameter_offset, 0,
                         data_count, data_offset, 0, 0].pack('v*')
          trans2_params = [0x0300, 3, 1, 0, 74].pack('v*')
          entry1 = "\x98\x5c\x38\x70\x98\x5c\x00\x00\x98\x5c\x39\x70" \
                   "\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x01".b + '.'
          entry2 = "\x98\x5c\x38\x70\x98\x5c\x00\x00\x98\x5c\x39\x70" \
                   "\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x02".b + '..'
          entry3 = "\x98\x5c\x40\x70\x98\x5c\x00\x00\x98\x5c\x4c\x70" \
                   "\x16\x00\x00\x00\x16\x00\x00\x00\x20\x00\x0c".b + 'FLAG.TXT.txt'
          trans2_data = entry1 + "\x00".b + entry2 + "\x00".b + entry3 + "\x00".b
          raise "data_count mismatch" unless trans2_data.bytesize == data_count
          byte_count_value = 10 + 1 + data_count # 0 pad1 + params + 1 pad2 + data
          smb_header + [10].pack('C') + param_block +
            [byte_count_value].pack('v') + trans2_params + "\x00".b + trans2_data
        end

        it 'parses the entries that BinData would otherwise drop due to missing pad1' do
          allow(client).to receive(:send_recv).and_return(build_win9x_find_first2_raw)
          results = tree.list(type: info_standard)
          expect(results.map { |r| r.file_name.to_s }).to eq(['.', '..', 'FLAG.TXT.txt'])
          expect(results.last.data_size).to eq 22
        end
      end
    end
  end

  describe '#set_unix_link' do
    let(:set_path_response) { RubySMB::SMB1::Packet::Trans2::SetPathInformationResponse.new }

    before :each do
      # Stub out the CIFS UNIX Extensions handshake — covered separately below.
      allow(tree).to receive(:enable_cifs_unix_extensions)
      allow(client).to receive(:send_recv)
      allow(RubySMB::SMB1::Packet::Trans2::SetPathInformationResponse).to receive(:read).and_return(set_path_response)
    end

    it 'performs the CIFS UNIX Extensions handshake before issuing the symlink request' do
      call_order = []
      allow(tree).to receive(:enable_cifs_unix_extensions) { call_order << :handshake }
      allow(client).to receive(:send_recv) { call_order << :set_path; '' }
      tree.set_unix_link(symlink: 'escape', target: '../../etc')
      expect(call_order).to eq([:handshake, :set_path])
    end

    it 'sends a Trans2 SetPathInformationRequest with the UNIX_LINK info level' do
      allow(client).to receive(:send_recv) do |request|
        expect(request).to be_a(RubySMB::SMB1::Packet::Trans2::SetPathInformationRequest)
        expect(request.data_block.trans2_parameters.information_level).to(
          eq(RubySMB::SMB1::Packet::Trans2::SetInformationLevel::SMB_SET_FILE_UNIX_LINK)
        )
      end
      tree.set_unix_link(symlink: 'escape', target: '../../etc')
    end

    it 'sets the Tree ID on the request' do
      allow(client).to receive(:send_recv) do |request|
        expect(request.smb_header.tid).to eq(tree.id)
      end
      tree.set_unix_link(symlink: 'escape', target: '../../etc')
    end

    it 'encodes the symlink path and target as raw byte strings (non-unicode)' do
      allow(client).to receive(:send_recv) do |request|
        raw = request.to_binary_s
        expect(request.smb_header.flags2.unicode).to eq(0)
        expect(raw).to include('escape'.b)
        expect(raw).to include('../../etc'.b)
        expect(raw).not_to include('escape'.encode('UTF-16LE').b)
      end
      tree.set_unix_link(symlink: 'escape', target: '../../etc')
    end

    it 'returns STATUS_SUCCESS on a successful response' do
      expect(tree.set_unix_link(symlink: 'escape', target: '../../etc'))
        .to eq(WindowsError::NTStatus::STATUS_SUCCESS)
    end

    context 'when the server returns a non-Trans2 response packet' do
      it 'raises InvalidPacket' do
        allow(set_path_response).to receive(:valid?).and_return(false)
        expect {
          tree.set_unix_link(symlink: 'escape', target: '../../etc')
        }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    context 'when the response has a non-success status code' do
      it 'raises UnexpectedStatusCode' do
        set_path_response.smb_header.nt_status =
          WindowsError::NTStatus::STATUS_ACCESS_DENIED.value
        expect {
          tree.set_unix_link(symlink: 'escape', target: '../../etc')
        }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
      end
    end
  end

  describe '#enable_cifs_unix_extensions' do
    let(:query_response) { RubySMB::SMB1::Packet::Trans2::QueryFsInformationResponse.new }
    let(:set_response)   { RubySMB::SMB1::Packet::Trans2::SetFsInformationResponse.new }

    before :each do
      # Server advertises major=1, minor=0, caps=0x0000_0000_0000_017B
      info = RubySMB::SMB1::Packet::Trans2::QueryFsInformationLevel::QueryFsCifsUnixInfo.new
      info.major_version = 1
      info.minor_version = 0
      info.capabilities  = 0x17B
      query_response.data_block.trans2_data.buffer = info.to_binary_s
      allow(RubySMB::SMB1::Packet::Trans2::QueryFsInformationResponse).to receive(:read).and_return(query_response)
      allow(RubySMB::SMB1::Packet::Trans2::SetFsInformationResponse).to receive(:read).and_return(set_response)
    end

    it 'queries the server for CIFS UNIX info and then echoes the capability bits back via SET_CIFS_UNIX_INFO' do
      sent = []
      allow(client).to receive(:send_recv) do |req|
        sent << req
        ''
      end
      tree.enable_cifs_unix_extensions

      expect(sent[0]).to be_a(RubySMB::SMB1::Packet::Trans2::QueryFsInformationRequest)
      expect(sent[0].data_block.trans2_parameters.information_level).to(
        eq(RubySMB::SMB1::Packet::Trans2::QueryFsInformationLevel::SMB_QUERY_CIFS_UNIX_INFO)
      )

      expect(sent[1]).to be_a(RubySMB::SMB1::Packet::Trans2::SetFsInformationRequest)
      expect(sent[1].data_block.trans2_parameters.information_level).to(
        eq(RubySMB::SMB1::Packet::Trans2::SetFsInformationLevel::SMB_SET_CIFS_UNIX_INFO)
      )
      echoed = RubySMB::SMB1::Packet::Trans2::QueryFsInformationLevel::QueryFsCifsUnixInfo.read(
        sent[1].data_block.trans2_data.buffer
      )
      expect(echoed.major_version).to eq(1)
      expect(echoed.minor_version).to eq(0)
      expect(echoed.capabilities).to eq(0x17B)
    end

    it 'raises UnexpectedStatusCode when the QUERY leg fails' do
      query_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_ACCESS_DENIED.value
      allow(client).to receive(:send_recv).and_return('')
      expect { tree.enable_cifs_unix_extensions }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
    end

    it 'raises UnexpectedStatusCode when the SET leg fails' do
      set_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_PARAMETER.value
      allow(client).to receive(:send_recv).and_return('')
      expect { tree.enable_cifs_unix_extensions }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
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

  describe '#set_find_params' do
    let(:find_first2_req) { RubySMB::SMB1::Packet::Trans2::FindFirst2Request.new }
    let(:modified_request) { tree.send(:set_find_params, find_first2_req) }

    it 'sets #data_count to 0' do
      expect(modified_request.parameter_block.data_count).to eq 0
    end

    it 'sets #data_offset to 0' do
      expect(modified_request.parameter_block.data_offset).to eq 0
    end

    it 'sets #total_parameter_count to #parameter_count value' do
      find_first2_req.parameter_block.parameter_count = 10
      expect(modified_request.parameter_block.total_parameter_count).to eq 10
    end

    it 'sets #max_parameter_count to #parameter_count value' do
      find_first2_req.parameter_block.parameter_count = 10
      expect(modified_request.parameter_block.max_parameter_count).to eq 10
    end

    it 'sets #max_data_count to the minimum of 16,384 and server_max_buffer_size' do
      expect(modified_request.parameter_block.max_data_count).to eq(
        [16_384, client.server_max_buffer_size].min
      )
    end
  end

  describe '#open_file (SMB_COM_OPEN_ANDX fallback)' do
    # Win9x and other LAN-Manager-era servers don't advertise the NT SMBs
    # capability, so #_open dispatches to #_open_andx instead of NT_CREATE_ANDX.
    let(:open_andx_response) do
      packet = RubySMB::SMB1::Packet::OpenAndxResponse.new
      packet.smb_header.nt_status = 0
      packet.parameter_block.fid             = 0x4242
      packet.parameter_block.file_data_size  = 1234
      packet.parameter_block.resource_type   = RubySMB::SMB1::ResourceType::DISK
      packet
    end

    before :example do
      client.server_supports_nt_smbs = false
    end

    it 'builds the OPEN_ANDX request without raising NoMethodError on bit-field assignment' do
      allow(client).to receive(:send_recv).and_return(open_andx_response.to_binary_s)
      expect { tree.open_file(filename: 'HELLO.TXT') }.not_to raise_error
    end

    it 'serializes search_attributes / file_attributes as SMB_FILE_ATTRIBUTES bit-fields' do
      sent = nil
      allow(client).to receive(:send_recv) do |req|
        sent = req
        open_andx_response.to_binary_s
      end
      tree.open_file(filename: 'HELLO.TXT')

      # 0x0016 = directory | system | hidden in the SMB_FILE_ATTRIBUTES search half.
      expect(sent.parameter_block.search_attributes.directory).to eq 1
      expect(sent.parameter_block.search_attributes.system).to    eq 1
      expect(sent.parameter_block.search_attributes.hidden).to    eq 1
      expect(sent.parameter_block.search_attributes.to_binary_s).to eq([0x0016].pack('v'))

      # Read-only open: file_attributes mask is zeroed.
      expect(sent.parameter_block.file_attributes.to_binary_s).to eq([0x0000].pack('v'))
    end

    it 'sets the SMB_FILE_ATTRIBUTE_ARCHIVE bit when opened for write' do
      allow(client).to receive(:send_recv).and_return(open_andx_response.to_binary_s)
      sent = nil
      allow(client).to receive(:send_recv) do |req|
        sent = req
        open_andx_response.to_binary_s
      end
      tree.open_file(filename: 'HELLO.TXT', write: true)

      expect(sent.parameter_block.file_attributes.to_binary_s).to eq([0x0020].pack('v'))
      expect(sent.parameter_block.file_attributes.archive).to eq 1
    end

    it 'returns a File handle whose FID and size come from the OPEN_ANDX response' do
      allow(client).to receive(:send_recv).and_return(open_andx_response.to_binary_s)
      file = tree.open_file(filename: 'HELLO.TXT')
      expect(file).to be_a(RubySMB::SMB1::File)
      expect(file.fid).to eq 0x4242
      expect(file.size).to eq 1234
    end
  end

  describe '#open_pipe' do
    let(:opts) { { filename: 'test', write: true } }
    before :example do
      allow(tree).to receive(:_open)
    end

    it 'calls #open_file with the provided options' do
      opts[:filename] ='\\test'
      expect(tree).to receive(:_open).with(opts)
      tree.open_pipe(**opts)
    end

    it 'prepends the filename with \\ if needed' do
      expect(tree).to receive(:_open).with(filename: '\\test', write: true)
      tree.open_pipe(**opts)
    end

    it 'does not modify the original option hash' do
      tree.open_pipe(**opts)
      expect(opts).to eq( { filename: 'test', write: true } )
    end
  end
end
