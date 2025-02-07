module RubySMB
  module Dcerpc
    module Gkdi

      # [2.1 Transport](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/2ca63ad2-2464-4a41-ba84-2e0270e95e86)
      UUID = 'b9785960-524f-11df-8b6d-83dcded72085'
      VER_MAJOR = 1
      VER_MINOR = 0

      # Operation numbers
      GKDI_GET_KEY = 0x0000

      require 'ruby_smb/dcerpc/gkdi/gkdi_get_key_request'
      require 'ruby_smb/dcerpc/gkdi/gkdi_get_key_response'
      require 'ruby_smb/dcerpc/gkdi/gkdi_group_key_envelope'

      def gkdi_get_key(target_sd, root_key_id, l0_key_id, l1_key_id, l2_key_id)
        target_sd = target_sd.to_binary_s if target_sd.respond_to?(:to_binary_s)

        gkdi_get_key_request = GkdiGetKeyRequest.new(
          cb_target_sd: target_sd.length,
          pb_target_sd: target_sd.unpack('C*'),
          p_root_key_id: root_key_id,
          l0_key_id: l0_key_id,
          l1_key_id: l1_key_id,
          l2_key_id: l2_key_id
        )

        response = dcerpc_request(
          gkdi_get_key_request,
          auth_level: @auth_level,
          auth_type: @auth_type
        )
        begin
          gkdi_get_key_response = GkdiGetKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading CertServerRequestResponse'
        end
        unless gkdi_get_key_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          status_code = WindowsError::Win32.find_by_retval(gkdi_get_key_response.error_status.value).first
          raise RubySMB::Dcerpc::Error::GkdiError.new(
            "Error returned with gkdi_get_key: #{status_code}",
            status_code: status_code
          )
        end

        GkdiGroupKeyEnvelope.read(gkdi_get_key_response.pbb_out.snapshot.pack('C*'))
      end

    end
  end
end
