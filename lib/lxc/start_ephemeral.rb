module LXC
  class ContainerError < StandardError; end

  class << self
    def start_ephemeral(original_container_name, target_container_name, opts={})
      orig = LXC::Container.new(original_container_name)
      dest = LXC::Container.new(target_container_name)
      raise ContainerError.new("#{original_container_name} is not present. Exiting..") unless orig.defined?
      raise ContainerError.new("#{target_container_name} is already present. Exiting..") if dest.defined?

      dest_path = File.join(LXC.global_config_item('lxc.lxcpath'), target_container_name)
      Dir.mkdir(dest_path, 0770)

      dest.load_config(orig.config_file_name)

      dest.set_config_item("lxc.utsname", dest.name)
      dest.set_config_item("lxc.rootfs", File.join(dest_path, "rootfs"))

      dest.config_item("lxc.network").each_with_index do |network_type, index|
        dest.set_config_item("lxc.network.#{index}.hwaddr", random_mac) if dest.config_item("lxc.network.#{index}.hwaddr")
      end

      create_pre_mount(orig, dest, opts)

      create_post_stop(orig, dest, opts)

      dest.save_config

      dest.start(daemonize: opts[:daemonize])

      unless dest.wait(:running, 5)
        dest.stop
        dest.destroy if dest.defined?
        raise ContainerError.new("The container '#{dest.name}' failed to start.")
      end

    rescue => e
      raise ContainerError.new("Unexpected error when starting container. The error was: #{e}")
    end

    private

    def new_overlay?
      @new_overlay ||= File.open('/proc/filesystems').grep(/^nodev\s+overlay$/).any?
    end

    def random_mac
      mac = [0x00, 0x16, 0x3e,
             SecureRandom.random_number(0x7f),
             SecureRandom.random_number(0xff),
             SecureRandom.random_number(0xff)
      ]
      mac.map {|number| number.to_s(16) }.join(':')
    end

    def create_pre_mount(orig, dest, opts)
      dest_path = File.join(LXC.global_config_item('lxc.lxcpath'), dest.name)
      overlay_dirs = [[orig.config_item("lxc.rootfs"), File.join(dest_path, "rootfs")]]
      File.open(File.join(dest_path, 'pre-mount'), 'w+', 0755) do |pre_mount|
        pre_mount.puts "#!/bin/sh"
        pre_mount.puts %Q{LXC_DIR="#{dest_path}"}
        pre_mount.puts %Q{LXC_BASE="#{orig.name}"}
        pre_mount.puts %Q{LXC_NAME="#{dest.name}"}
        overlay_dirs.each_with_index do |entry, count|
          tmpdir = File.join(dest_path, 'tmpfs')
          pre_mount.puts "mkdir -p #{tmpdir}"
          deltdir = File.join(tmpdir, "/delta#{count}")
          workdir = File.join(tmpdir, "/work#{count}")
          pre_mount.puts "mkdir -p #{deltdir} #{entry[1]} #{workdir if new_overlay?}"
          pre_mount.puts "getfacl -a #{entry[0]} | setfacl --set-file=- #{deltdir} || true"
          pre_mount.puts "getfacl -a #{entry[0]} | setfacl --set-file=- #{entry[1]} || true"

          if new_overlay?
            pre_mount.puts "mount -n -t overlay -oupperdir=#{deltdir},lowerdir=#{entry[0]},workdir=#{workdir} none #{entry[1]}"
          else
            pre_mount.puts "mount -n -t overlayfs -oupperdir=#{deltdir},lowerdir=#{entry[0]} none #{entry[1]}"
          end
        end

        bind_directories = opts[:bdir].nil? ? [] : opts[:bdir]
        bind_directories.each do |host_entry, container_entry|
          if Dir.exists?(host_entry)
            src_path = File.absolute_path(host_entry)
            dst_path = File.join(dest_path, 'rootfs', container_entry)
            pre_mount.puts "mkdir -p #{dst_path}"
            pre_mount.puts "mount -n --bind #{src_path} #{dst_path}"
          else
            raise "Couldn't locate #{host_entry} on the host"
          end
        end

        pre_mount.puts %Q{[ -e $LXC_DIR/configured ] && exit 0}
        pre_mount.puts %Q{for file in $LXC_DIR/rootfs/etc/hostname \\}
        pre_mount.puts %Q{  $LXC_DIR/rootfs/etc/hosts \\}
        pre_mount.puts %Q{  $LXC_DIR/rootfs/etc/sysconfig/network \\}
        pre_mount.puts %Q{  $LXC_DIR/rootfs/etc/sysconfig/network-scripts/ifcfg-eth0; do}
        pre_mount.puts %Q{    [ -f "$file" ] && sed -i -e "s/$LXC_BASE/$LXC_NAME/" $file}
        pre_mount.puts %Q{done}
        pre_mount.puts %Q{touch $LXC_DIR/configured}
      end

      dest.set_config_item("lxc.hook.pre-mount", File.join(dest_path, "pre-mount"))
    end

    def create_post_stop(orig, dest, opts)
      dest_path = File.join(LXC.global_config_item('lxc.lxcpath'), dest.name)
      File.open(File.join(dest_path, 'post-stop'), 'w+', 0755) do |post_stop|
        post_stop.puts %Q{[ -d #{dest_path} ] && rm -Rf "#{dest_path}"}
      end

      dest.set_config_item("lxc.hook.post-stop", File.join(dest_path, "post-stop"))
    end
  end
end
