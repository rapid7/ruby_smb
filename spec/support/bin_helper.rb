class String
  def hexlify
    self.b.bytes.map {|c| "%02x" % c.ord}.join
  end

  def unhexlify
    self.chars.each_slice(2).map {|c| c.join.to_i(16).chr}.join
  end
end
