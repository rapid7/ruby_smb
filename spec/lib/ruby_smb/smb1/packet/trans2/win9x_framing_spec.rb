require 'spec_helper'

RSpec.describe RubySMB::SMB1::Packet::Trans2::Win9xFraming do
  # FindFirst2Response is the first production consumer of the mixin; its
  # fixture data already covers every code path in #win9x_trans2_overrides
  # (zero-length buffer, on-wire match, server-reported mismatch, truncated
  # raw response). Using it here keeps the spec grounded in real field
  # layouts without standing up an anonymous host class.
  let(:info_std) do
    RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindInfoStandard
  end

  # Reusable fixtures: NT-style (with pad1=3) and Win9x-style (pad1=0) raw
  # FindFirst2Response frames carrying the same single-entry payload so the
  # overrides helper sees the same server-declared offsets differ from what
  # BinData positionally reads.
  let(:single_entry_bytes) do
    "\x98\x5c\x38\x70\x98\x5c\x00\x00\x98\x5c\x39\x70".b +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x01".b + '.'
  end
  let(:data_count) { single_entry_bytes.bytesize }

  def smb_header
    "\xffSMB\x32".b + "\x00".b * 4 + "\x98".b + "\x03\x60".b + ("\x00".b * 20)
  end

  def build_response(parameter_offset:, data_offset:, word_count:, pad1: 0, pad2: 0)
    # The concrete field layout of FindFirst2Response's parameter_block
    # changes with word_count: 11 words include a 1-entry setup array;
    # 10 words (Win9x style) omit it. trans2_parameters itself is a
    # fixed 10-byte struct (sid, search_count, eos, ea_err_off, last_name_off).
    trans2_params = [0x0300, 1, 1, 0, 0].pack('v*')
    pb_values = [10, data_count, 0, 10, parameter_offset, 0,
                 data_count, data_offset, 0]
    # word_count=11 → setup_count(1) + reserved2(0) + 1-word setup array
    # word_count=10 → setup_count(0) + reserved2(0), no setup array
    pb_tail = word_count == 11 ? "\x01\x00".b + [1].pack('v') : "\x00\x00".b
    param_block = pb_values.pack('v*') + pb_tail
    byte_count  = pad1 + 10 + pad2 + data_count
    smb_header + [word_count].pack('C') + param_block +
      [byte_count].pack('v') + ("\x00".b * pad1) + trans2_params +
      ("\x00".b * pad2) + single_entry_bytes
  end

  describe '#win9x_trans2_overrides' do
    context 'when BinData has already read the full buffer (NT-style server)' do
      it 'returns [nil, nil]' do
        # NT-era response: word_count=11 with 1-word setup, pad1=3, pad2=2
        # → trans2_parameters at offset 60, trans2_data at 72. BinData's
        # Trans2::DataBlock positional read lands exactly on the wire data.
        raw = build_response(
          parameter_offset: 60, data_offset: 72,
          word_count: 11, pad1: 3, pad2: 2
        )
        response = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.read(raw)
        expect(response.win9x_trans2_overrides(raw)).to eq([nil, nil])
      end
    end

    context 'when the server declared no trans2_data (data_count == 0)' do
      it 'returns [nil, nil]' do
        raw = build_response(
          parameter_offset: 60, data_offset: 72,
          word_count: 11, pad1: 3, pad2: 2
        )
        response = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.read(raw)
        response.parameter_block.data_count = 0
        expect(response.win9x_trans2_overrides(raw)).to eq([nil, nil])
      end
    end

    context 'when the server used Win9x-era framing (no pad1)' do
      it 'returns trans2_parameters re-read at the server-reported offset' do
        raw = build_response(
          parameter_offset: 55, data_offset: 66,
          word_count: 10, pad1: 0, pad2: 1
        )
        response = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.read(raw)
        params, = response.win9x_trans2_overrides(raw)
        expect(params).to be_a(RubySMB::SMB1::Packet::Trans2::FindFirst2ResponseTrans2Parameters)
        expect(params.sid).to          eq 0x0300
        expect(params.search_count).to eq 1
        expect(params.eos).to          eq 1
      end

      it 'returns the trans2_data bytes sliced from the server-reported offset' do
        raw = build_response(
          parameter_offset: 55, data_offset: 66,
          word_count: 10, pad1: 0, pad2: 1
        )
        response = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.read(raw)
        _, data_bytes = response.win9x_trans2_overrides(raw)
        expect(data_bytes).to eq single_entry_bytes
        # And #results can read entries from it through the buffer: kwarg.
        entries = response.results(info_std, unicode: false, buffer: data_bytes)
        expect(entries.length).to             eq 1
        expect(entries.first.file_name.to_s).to eq '.'
      end
    end

    context 'when the raw response is truncated before the server-reported offsets' do
      it 'returns [nil, nil] rather than raising' do
        raw = build_response(
          parameter_offset: 55, data_offset: 66,
          word_count: 10, pad1: 0, pad2: 1
        )
        response = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.read(raw)
        truncated = raw.byteslice(0, raw.bytesize - 20)
        expect(response.win9x_trans2_overrides(truncated)).to eq([nil, nil])
      end
    end
  end
end
