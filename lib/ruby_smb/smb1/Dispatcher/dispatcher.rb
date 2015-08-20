module RubySMB
module SMB1
class  Dispatcher
  attr_accessor :command

  def initialize(command)
    validate(command)
    @command = command
  end

  def transmit
    @command.transmit if command
  end

private

  def validate(command)
    raise ArguementError if command.nil?
  end

end
end
end
