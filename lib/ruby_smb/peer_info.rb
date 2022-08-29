module RubySMB
  module PeerInfo
    # Extract and store useful information about the peer/server from the
    # NTLM Type 2 (challenge) TargetInfo fields.
    #
    # @param target_info_str [String] the Target Info string
    def store_target_info(target_info_str)
      target_info = Net::NTLM::TargetInfo.new(target_info_str)
      {
        Net::NTLM::TargetInfo::MSV_AV_NB_COMPUTER_NAME  => :@default_name,
        Net::NTLM::TargetInfo::MSV_AV_NB_DOMAIN_NAME    => :@default_domain,
        Net::NTLM::TargetInfo::MSV_AV_DNS_COMPUTER_NAME => :@dns_host_name,
        Net::NTLM::TargetInfo::MSV_AV_DNS_DOMAIN_NAME   => :@dns_domain_name,
        Net::NTLM::TargetInfo::MSV_AV_DNS_TREE_NAME     => :@dns_tree_name
      }.each do |constant, attribute|
        if target_info.av_pairs[constant]
          value = target_info.av_pairs[constant].dup
          value.force_encoding('UTF-16LE')
          instance_variable_set(attribute, value.encode('UTF-8'))
        end
      end
    end

    # Extract the peer/server version number from the NTLM Type 2 (challenge)
    # Version field.
    #
    # @param version [String] the version number as a binary string
    # @return [String] the formatted version number (<major>.<minor>.<build>)
    def extract_os_version(version)
      begin
        os_version = RubySMB::NTLM::OSVersion.read(version)
      rescue IOError
        return ''
      end

      "#{os_version.major}.#{os_version.minor}.#{os_version.build}"
    end
  end
end
