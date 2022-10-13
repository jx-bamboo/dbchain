module Dbchain
  class Result
    def initialize(struct, success)
      @value = struct
      @success = success
    end

    def success?
      @success
    end

    attr_reader :value
  end
end
