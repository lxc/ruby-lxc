$:.unshift File.expand_path(File.join(File.dirname(__FILE__), 'lib'))

require 'test/unit'
require 'lxc'
require 'test_helpers'

if RUBY_VERSION.to_f > 1.8
  class TestLXCLongRunning < Test::Unit::TestCase
    include TestHelpers

    def setup
      if Process::Sys::geteuid != 0
        raise 'This test must be run as root'
      end
      @name = 'test'
      @container = LXC::Container.new(@name)
      @container.create('ubuntu') unless @container.defined?
      @container.start unless @container.running?
      @container.unfreeze
      # Destroy leftover snapshots so we don't take up the whole disk
      @container.snapshot_list.each do |snapshot, commentfile, timestamp, snapshotfile|
        @container.snapshot_destroy(snapshot)
      end
    end

  # TODO find a way to test unblockness for functions that don't run quite so long
  #  def test_add_device_node_allows_ruby_to_continue
  #    assert_long_running_function_does_not_block_ruby do
  #      @container.add_device_node('/dev/ttyS0')
  #    end
  #  end

    def test_attach_wait_true_allows_ruby_to_continue
      assert_long_running_function_does_not_block_ruby do
        @container.attach(:wait => true) do
          sleep(2)
        end
      end
    end

    def test_clone_allows_ruby_to_continue
      # Ensure the "cloned" VM does not exist
      cloned_name = "#{@name}_cloned"
      cloned_to_destroy = LXC::Container.new(cloned_name)
      cloned_to_destroy.destroy if cloned_to_destroy.defined?

      cloned = nil
      @container.stop
      begin
        assert_long_running_function_does_not_block_ruby do
          cloned = @container.clone(cloned_name)
        end
      ensure
        @container.start
      end
      # Verify that it did something
      assert(@container.name == @name, "original container name has changed from '#{@name}' to '#{@container.name}''")
      assert(@container.running?, "original container is not running")
      assert(cloned.name == cloned_name, "new container name should be '#{cloned_name}', is '#{cloned.name}'")
      assert(cloned.init_pid != @container.init_pid, "cloned container init pid is the same as the original!  Something ain't right.")
    end

  # TODO Unsure how to test this without attaching to the actual tty!  Must be a way to obtain a pipe or false tty of some sort.  Manual run reveals it works, however.
  #  def test_console_allows_ruby_to_continue
  #    assert_long_running_function_does_not_block_ruby do
  #      @container.console
  #    end
  #  end

    def test_destroy_allows_ruby_to_continue
      container = LXC::Container.new("test_destroy")
      container.create('ubuntu') if !container.defined?
      assert_long_running_function_does_not_block_ruby do
        container.destroy
      end
      assert(!container.defined?, "Destroy did not destroy the container!")
    end

  # TODO find a way to test unblockness for functions that don't run quite so long
  #  def test_freeze_allows_ruby_to_continue
  #    begin
  #      assert_long_running_function_does_not_block_ruby do
  #        @container.freeze
  #      end
  #    ensure
  #      @container.unfreeze
  #    end
  #  end

  # TODO find a way to test unblockness for functions that don't run quite so long
  #  def test_load_config_allows_ruby_to_continue
  #    File.open('/tmp/blah', 'w') do |file|
  #      file.write("\n\n\n\n")
  #    end
  #    begin
  #      container = LXC::Container.new('blahdeblah')
  #      assert_long_running_function_does_not_block_ruby do
  #        container.load_config('/tmp/blah')
  #      end
  #    ensure
  #      File.delete('/tmp/blah')
  #    end
  #  end

  # TODO find a way to test unblockness for functions that don't run quite so long
  #  def test_reboot_allows_ruby_to_continue
  #    assert_long_running_function_does_not_block_ruby do
  #      @container.reboot
  #    end
  #  end

  # TODO find a way to test unblockness for functions that don't run quite so long
  #  def test_remove_device_node_allows_ruby_to_continue
  #    assert_long_running_function_does_not_block_ruby do
  #      @container.remove_device_node('/dev/ttyS0')
  #    end
  #  end

  # TODO find a way to test unblockness for functions that don't run quite so long
  #  def test_save_config_allows_ruby_to_continue
  #    File.unlink('/tmp/blah') if File.exist?('/tmp/blah')
  #    assert_long_running_function_does_not_block_ruby do
  #      @container.save_config('/tmp/blah')
  #    end
  #    assert(File.exist?('/tmp/blah'), "save_config did not save /tmp/blah!")
  #  end

    def test_shutdown_allows_ruby_to_continue
      begin
        assert_long_running_function_does_not_block_ruby do
          @container.shutdown
        end
      ensure
        @container.start if !@container.running?
      end
    end

    def test_snapshot_allows_ruby_to_continue
      @container.stop
      begin
        assert_long_running_function_does_not_block_ruby do
          @container.snapshot
        end
      ensure
        @container.start
      end
    end

    def test_snapshot_destroy_allows_ruby_to_continue
      @container.stop
      begin
        snapshot = @container.snapshot
        assert_long_running_function_does_not_block_ruby do
          @container.snapshot_destroy(snapshot)
        end
      ensure
        @container.start
      end
    end

  # TODO find a way to test unblockness for functions that don't run quite so long
  #  def test_snapshot_list_allows_ruby_to_continue
  #    @container.stop
  #    begin
  #      snapshot = @container.snapshot
  #      assert_long_running_function_does_not_block_ruby do
  #        assert(@container.snapshot_list > 0, "Snapshot list was empty!"
  #      end
  #    ensure
  #      @container.start
  #    end
  #  end

    def test_snapshot_restore_allows_ruby_to_continue
      @container.stop
      begin
        snapshot = @container.snapshot
        assert_long_running_function_does_not_block_ruby do
          @container.snapshot_restore(snapshot)
        end
      ensure
        @container.start
      end
    end

    def test_start_allows_ruby_to_continue
      @container.stop
      assert_long_running_function_does_not_block_ruby do
        @container.start
      end
      assert(@container.running?, "Start did not start container! State = #{@container.state}")
    end

  # TODO find a way to test unblockness for functions that don't run quite so long
  #  def test_stop_allows_ruby_to_continue
  #    begin
  #      assert_long_running_function_does_not_block_ruby do
  #        @container.stop
  #      end
  #      assert(!@container.running?, "Stop did not stop container! State = #{@container.state}")
  #    ensure
  #      @container.start if !@container.running?
  #    end
  #  end

  # TODO find a way to test unblockness for functions that don't run quite so long
  #  def test_unfreeze_allows_ruby_to_continue
  #    @container.freeze
  #    assert_long_running_function_does_not_block_ruby do
  #      @container.unfreeze
  #    end
  #  end

    def test_wait_allows_ruby_to_continue
      t = Thread.new do
        sleep(0.5)
        @container.stop
      end
      begin
        assert_long_running_function_does_not_block_ruby do
          @container.wait(:stopped, 2)
        end
        assert(@container.state == :stopped, "Container never stopped! State is now #{@container.state.inspect}")
      ensure
        t.join
        @container.start if !@container.running?
      end
    end
  end
end
