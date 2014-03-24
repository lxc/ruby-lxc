require 'lxc'
require 'test/unit/assertions'

module TestHelpers
  def assert_long_running_function_does_not_block_ruby(&block)
    r, w = IO.pipe
    begin
      # Write something after a very short period, but only if Ruby isn't blocked!
      t = Thread.new do
        sleep(0.001)
        # Sleep twice so that if the function is blocking and we wake up just
        # after block.call(c) somehow, we will go back to sleep briefly and
        # allow B to be written
        sleep(0.001)
        w.write('A')
      end
      # Call the function and see if Ruby gets blocked
      block.call
      w.write('B')
      chars = r.read(2)
      assert(chars == 'AB', "Expected thread to write before block finished, but it did not. Expected 'AB', got '#{chars}'")
    ensure
      r.close
      w.close
    end
  end
end
