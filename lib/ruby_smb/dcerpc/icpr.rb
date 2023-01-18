module RubySMB
  module Dcerpc
    module Icpr

      # [3.2.4.1 ICertPassage Interface](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/d98e6cfb-87ba-4915-b3ec-a1b7c6129a53)
      UUID = '91ae6020-9e3c-11cf-8d7c-00aa00c091be'
      VER_MAJOR = 0
      VER_MINOR = 0

      # Operation numbers
      CERT_SERVER_REQUEST = 0x0000

      # Disposition constants, see
      # [3.2.1.4.2.1 ICertRequestD::Request (Opnum 3)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/dbb2e78f-7630-4615-92c4-6734fccfc5a6)
      CR_DISP_ISSUED           = 0x0003
      CR_DISP_UNDER_SUBMISSION = 0x0005

      # [2.2.2.2 CERTTRANSBLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/d6bee093-d862-4122-8f2b-7b49102097dc)
      # (actually defined in MS-WCCE)
      class CertTransBlob < Ndr::NdrStruct
        endian :little
        default_parameter  byte_align: 4

        ndr_uint32              :cb, initial_value: -> { pb.length }
        ndr_byte_conf_array_ptr :pb

        def buffer
          pb.to_ary.pack('C*')
        end
      end

      require 'ruby_smb/dcerpc/icpr/cert_server_request_request'
      require 'ruby_smb/dcerpc/icpr/cert_server_request_response'

      def cert_server_request(attributes:, authority:, csr:)
        cert_server_request_request = CertServerRequestRequest.new(
          pwsz_authority: authority,
          pctb_attribs: { pb: (RubySMB::Utils.safe_encode(attributes.map { |k,v| "#{k}:#{v}" }.join("\n"), 'UTF-16le').force_encoding('ASCII-8bit') + "\x00\x00".b) },
          pctb_request: { pb: csr.to_der }
        )

        response = dcerpc_request(
          cert_server_request_request,
          auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
          auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
        )
        begin
          cert_server_request_response = CertServerRequestResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading CertServerRequestResponse'
        end

        ret = {
          certificate: nil,
          disposition: cert_server_request_response.pdw_disposition.value,
          disposition_message: cert_server_request_response.pctb_disposition_message.buffer.chomp("\x00\x00").force_encoding('utf-16le').encode,
          status: {
            CR_DISP_ISSUED => :issued,
            CR_DISP_UNDER_SUBMISSION => :submitted,
          }.fetch(cert_server_request_response.pdw_disposition.value, :error)
        }

        # note: error_status == RPC_S_BINDING_HAS_NO_AUTH when not properly bound
        if ret[:status] == :error
          unless cert_server_request_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
            error_status = cert_server_request_response.error_status.value
            status_code = WindowsError::Win32.find_by_retval(error_status).first
            if status_code.nil? && (fault_name = RubySMB::Dcerpc::Fault::Status.name(error_status))
              status_code = WindowsError::ErrorCode.new(fault_name.to_s, error_status, 'DCERPC fault')
            end
            raise RubySMB::Dcerpc::Error::IcprError.new(
              "Error returned with cert_server_request: #{status_code || "0x#{error_status.to_s(16).rjust(8, '0')}"}",
              status_code: status_code
            )
          end
        elsif !cert_server_request_response.pctb_encoded_cert.buffer.empty?
          ret[:certificate] = OpenSSL::X509::Certificate.new(cert_server_request_response.pctb_encoded_cert.buffer)
        end

        ret
      end

    end
  end
end
