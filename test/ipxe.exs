#### One Elixir script / file containing everything needed for DHCP/TFTP PXE Booting with cloud-init initialization ####
# Build bin/undionly.kpxe with IPXE "make bin/undionly.kpxe EMBED=chain.ipxe"
# with chain.ipxe containing :
#    #!ipxe
#    echo IPXE KBRW Server
#    dhcp
#    chain http://192.168.56.1/main.ipxe

defmodule Conf do
  def srv_ip, do:
    {192,168,56,1}
  def ip_range, do:
    ({a,b,c,_} = srv_ip ; Stream.map(101..254,&{a,b,c,&1}))
  def broadcast, do:
    {192,168,56,255}
  def dhcp_offer_opts, do:
    %{lease_time: 3600, renewal_time: 1800, rebinding_time: 3000, 
      subnet_mask: {255,255,255,0}, broadcast_address: broadcast,
      dns_server: {8,8,8,8}, domain_name: "kbrw.org"}
  def sshkey, do:
    "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwWQ5bra9i1Nm9KNBFzogEP3zORhGDrxbx2N/K/bgLy9/wXT6C8I7DmzA3hkqZ6TMhv9DyGAfBRmRMIg8QjHGvsD9kSzmGK70SGz1aX1wwiuz4i6WnFIEnr3iCthECjzqrKSwzt+8wbHTE59ki2HHWzmK8uncZsN37KTThU95C4mcHIldIAixEgVmaFEjMLAig2ZIE3f0sONcHEdwwhkXnR8HM36Xqg6kBVOz642izS8SnAoHOLM6ZfHMX37FOUuqL0kuCQ9/IqF4B1ECbIqe3kaZFZjBhelf2PDvMsLKsujlPCkvTK8Gc7eQeJFBBto+qa6mObZxd7C+nvQqP8IcrQ== awetzel@MacBook-Pro-de-jerome-benoliel.local"
  def hostname({_,_,_,i}=_ip), do:
    "core#{i}"
  def srv_ip_str, do:
    (srv_ip() |> Tuple.to_list |> Enum.join("."))

  def ipxe_script, do: """
    #!ipxe
  
    #set base-url http://stable.release.core-os.net/amd64-usr/current
    set base-url http://#{srv_ip_str}
    
    #kernel ${base-url}/arcore-kernel initrd=arcore.img vconsole.keymap=fr arcore.net="[Match]\\nName=eth0\\n[Network]\\nDHCP=ipv4" arcore.net="[Match]\\nName=eth1\\n[Network]\\nDHCP=ipv4" arcore.fs=http://#{srv_ip_str}/hostfs systemd.journald.forward_to_console=1 systemd.log_target=console
    #kernel ${base-url}/arcore-kernel initrd=arcore.img vconsole.keymap=fr arcore.net="[Match]\\nName=eth0\\n[Network]\\nDHCP=ipv4" arcore.net="[Match]\\nName=eth1\\n[Network]\\nDHCP=ipv4" arcore.fs=http://#{srv_ip_str}/hostfs systemd.log_level=debug systemd.log_target=console
    #kernel ${base-url}/arcore-kernel initrd=arcore.img vconsole.keymap=fr arcore.net="[Match]\\nName=eth0\\n[Network]\\nDHCP=ipv4" arcore.net="[Match]\\nName=eth1\\n[Network]\\nDHCP=ipv4" arcore.fs=http://#{srv_ip_str}/hostfs
    #kernel ${base-url}/arcore-kernel initrd=arcore.img vconsole.keymap=fr arcore.net="[Match]\\nName=eth0\\n[Network]\\nDHCP=ipv4" arcore.net="[Match]\\nName=eth1\\n[Network]\\nDHCP=ipv4" arcore.fs=http://#{srv_ip_str}/hostfs arcore.install arcore.alert=http://#{srv_ip_str}/alert
    kernel ${base-url}/arcore-kernel initrd=arcore.img vconsole.keymap=fr arcore.net="[Match]\\nName=eth0\\n[Network]\\nDHCP=ipv4" arcore.net="[Match]\\nName=eth1\\n[Network]\\nDHCP=ipv4" arcore.fs=http://#{srv_ip_str}/hostfs arcore.alert=http://#{srv_ip_str}/alert
    initrd ${base-url}/arcore.img
    boot    
    """
    ##!ipxe
  
    ##set base-url http://stable.release.core-os.net/amd64-usr/current
    #set base-url http://#{srv_ip_str}
    #kernel ${base-url}/coreos_production_pxe.vmlinuz initrd=coreos_production_pxe_image.cpio.gz sshkey="#{sshkey()}"
    #initrd ${base-url}/coreos_production_pxe_image.cpio.gz
    #boot    
    #"""
    #  def ipxe_script, do: """
    #    #!ipxe
    #
    #    #set base-url http://stable.release.core-os.net/amd64-usr/current
    #    set base-url http://#{srv_ip_str}
    #    kernel ${base-url}/coreos_production_pxe.vmlinuz initrd=coreos_production_pxe_image.cpio.gz sshkey="#{sshkey()}"
    #    initrd ${base-url}/coreos_production_pxe_image.cpio.gz
    #    boot    
    #    """
  def host_fs do
    to_tgz %{
      "/install.sh"=> """
      echo "hello ARCORE Host installation"
      mdadm --create --verbose /dev/md0 --level=0 --raid-devices=2 /dev/sda /dev/sdb
      mkfs.btrfs /dev/md0
      mdadm --create --verbose /dev/md1 --level=0 --raid-devices=2 /dev/sdc /dev/sdd
      mkfs.btrfs /dev/md1
      mdadm --detail --scan
      """,
      "/etc/udev/rules.d/99-ovh.rules"=> """
      ACTION=="add", SUBSYSTEM=="net", KERNEL=="eth0", NAME:="vrack"
      ACTION=="add", SUBSYSTEM=="net", KERNEL=="eth1", NAME:="public"
      """,
      "/etc/systemd/network"=>%{
        "0-public.network"=> """
        [Match]
        Name=public
        [Network]
        DHCP=ipv4
        """,
        "1-private.network"=> """
        [Match]
        Name=vrack
        [Network]
        DHCP=ipv4
        """
      },
      "/etc/systemd/system"=>%{
        "mnt-hdd.mount"=>"""
        [Mount]
        What=/dev/md0
        Where=/mnt/hdd
        """,
        "mnt-ssd.mount"=>"""
        [Mount]
        What=/dev/md1
        Where=/mnt/ssd
        """,
        "local-fs.target.requires"=>%{
          "mnt-hdd.mount"=> {:link,"../mnt-hdd.mount"},
          "mnt-ssd.mount"=> {:link,"../mnt-hdd.mount"},
        }
      },
      "/etc/mdadm/mdadm.conf"=> """
        DEVICE partitions
        ARRAY /dev/md0 metadata=1.2 name=archlinux:0 UUID=f21f7807:7059b2f0:a8379986:fb286f7b
        ARRAY /dev/md1 metadata=1.2 name=archlinux:1 UUID=7ea3fdc7:f392080a:639dd512:686746e0
        """
    }
  end

  def to_tgz(map) do
    tmp = "#{System.tmp_dir!}/#{:crypto.strong_rand_bytes(6) |> Base.url_encode64}"
    File.mkdir_p!(tmp)
    to_flat_map(map,[]) |> Enum.map(fn {path,val}->
      File.mkdir_p!(tmp<>"/"<>Path.dirname(path))
      case val do
        v when is_binary(v)->
          File.write!(tmp<>"/"<>path,v)
        {:link,link}->
          :ok = File.ln_s(link,tmp<>"/"<>path)
      end
    end)
    IO.puts tmp
    {_,0} = System.cmd("tar",["czf","archive.tgz"] ++ Enum.map(Path.wildcard(tmp<>"/*"),&String.replace(&1,tmp,".")),into: IO.stream(:stdio,:line), cd: tmp)
    ret = File.read!(tmp<>"/archive.tgz")
    #File.rm_rf!(tmp)
    ret
  end
  defp to_flat_map(%{}=map,path), do: Enum.flat_map(map,fn {k,v}-> to_flat_map(v,path++[k]) end)
  defp to_flat_map({:link,link},path), do: [{path |> Enum.join("/") ,{:link,link}}]
  defp to_flat_map(other,path) when is_binary(other), do: [{path |> Enum.join("/") ,other}]
end

defmodule PXE.HTTP do
  def start_link(ip,port) do
    spawn_link(fn-> 
      {:ok,s} = :gen_tcp.listen(port, active: false, mode: :binary, ip: ip)
      server(s)
    end)
  end
  def send_chunk(chunk,conn), do: 
    :gen_tcp.send(conn,[Integer.to_string(byte_size(chunk),16),"\r\n",chunk,"\r\n"])
  def send_chunks(<<chunk::binary-250000,rest::binary>>,conn), do: (send_chunk(chunk,conn); send_chunks(rest,conn))
  def send_chunks("",conn), do: send_chunk("",conn)
  def send_chunks(chunk, conn), do: (send_chunk(chunk,conn); send_chunk("",conn))

  def server(s) do
    {:ok, conn} = :gen_tcp.accept(s)
    spawn(fn-> 
      {:ok,req} = :gen_tcp.recv(conn, 0)
      case req do
        "GET "<>rest->
          [path,rest] = String.split(rest," ", parts: 2)
          IO.puts "HTTP query for #{path}"
          body = case path do
            "/main.ipxe"-> Conf.ipxe_script
            "/hostfs"-> Conf.host_fs
            other-> File.read!("bin#{other}")
          end
          :gen_tcp.send(conn, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
          send_chunks(body,conn)
        "POST "<>rest->
          [path,_] = String.split(rest," ", parts: 2)
          IO.puts "HTTP query for #{path}"
          [_,body] = String.split(rest,"\r\n\r\n",parts: 2)
          IO.puts body
          :gen_tcp.send(conn, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/octet-stream; charset=UTF-8\r\n\r\nOK")
        _ ->
          IO.puts "Cannot respond to HTTP query #{req}"
          :gen_tcp.send(conn, "HTTP/1.1 400 OK\r\nConnection: close\r\nContent-Type: application/octet-stream; charset=UTF-8\r\n\r\nNOT OK")
      end
      :gen_tcp.close(conn)
    end)
    server(s)
  end
end

defmodule PXE.TFTP do
  def open(_,_,file,_,_,_) do
    case File.open("bin/#{file}",[read_ahead: 1_000_000]) do
      {:ok,fp}->{:ok,[],{:fp,fp,0}}
      {:error,_}->{:error,{:enoent,''}}
    end
  end
  def read({:fp,f,s}) do
    case IO.binread(f,512) do
      :eof->
        File.close(f)
        {:last,"",s}
      data when byte_size(data) == 512->
        {:more,IO.iodata_to_binary(data),{:fp,f,s+512}}
      data when byte_size(data) < 512->
        File.close(f)
        {:last,data,s + byte_size(data)}
    end
  end
  def read({:str,bin,s}) when byte_size(bin) < 512, do: {:last,bin,s+byte_size(bin)}
  def read({:str,<<bin::binary-size(512),rest::binary>>,s}), do: {:more,bin,{:str,rest,s+512}}
end

defmodule PXE.DHCP do
  defmodule Lease do
    @lease_file "bin/dhcp_lease"
    def get(%{chaddr: chaddr},%{}) do
      prev_lease = case File.read(@lease_file) do
        {:ok,bin}->:erlang.binary_to_term(bin)
        {:error,_}->%{}
      end
      ip = case prev_lease[chaddr] do
        nil-> # NO LEASE, find the smallest not used IP
          used_ips = Dict.values(prev_lease)
          new_ip = Conf.ip_range |> Enum.find(& not &1 in used_ips)
          lease = Dict.put(prev_lease,chaddr,new_ip)
          File.write!(@lease_file,:erlang.term_to_binary(lease))
          hosts = File.read!("/etc/hosts")
          marker = "## SA_HOST_TEST_"
          domains = "#{marker}\n#{lease |> Enum.map(fn {_,ip}-> "#{ip |> Tuple.to_list |> Enum.join(".")}\t#{Conf.hostname ip}" end) |> Enum.join("\n")}\n#{marker}"
          File.write!("/etc/hosts",
            if(String.contains?(hosts,marker)) do
              String.replace(hosts,~r/#{marker}.*#{marker}/s,domains)
            else
              hosts <> "\n\n" <> domains
            end)
          new_ip
        ip-> ip
      end
      %{ip_addr: ip, chaddr: chaddr, options: Conf.dhcp_offer_opts}
    end
  end
  defmodule Packet do
    defstruct msg_type: nil, file: "", requested_ip: {0, 0, 0, 0},op: 0, htype: 0, hlen: 0, hops: 0, xid: 0, secs: 0, flags: 0, ciaddr: {0, 0, 0, 0}, yiaddr: {0, 0, 0, 0}, siaddr: {0, 0, 0, 0}, giaddr: {0, 0, 0, 0}, chaddr: {0, 0, 0, 0, 0, 0},sname: 0, options: []

    @opts %{1=>:subnet_mask,2=>:time_offset,3=>:router,6=>:dns_server,12=>:host_name,15=>:domain_name,28=>:broadcast_address,43=>:vendor_opts,50=>:requested_ip_address,51=>:lease_time,53=>:message_type,54=>:server_id,55=>:parameter_request,57=>:max_message_size,58=>:renewal_time,59=>:rebinding_time,60=>:class_id,61=>:client_id,77=>:user_class,93=>:pxe_arch,94=>:pxe_version,97=>:pxe_guid,175=> :ipxe}
    @opts_id @opts |> Enum.map(fn {k,v}->{v,k} end) |> Enum.into(%{})
    @vendor_opts %{1=>:pxe_ftp_ip,2=>:pxe_ftp_cport,3=>:pxe_ftp_sport,4=>:pxe_ftp_tmout,5=>:pxe_ftp_delay,6=>:pxe_discovery_control,7=>:discover_mcast_addr,8=>:pxe_boot_servers,9=>:pxe_boot_menus,10=>:pxe_menu_prompt,11=>:pxe_mcast_addrs,12=>:pxe_cred_types,71=>:pxe_boot_item}
    @vendor_opts_id @vendor_opts |> Enum.map(fn {k,v}->{v,k} end) |> Enum.into(%{})
    def decode_packet(<<op::8,htype::8,hlen::8,hops::8,xid::32,secs::16,flags::16-big,ciaddr::4-binary,yiaddr::4-binary,siaddr::4-binary,giaddr::4-binary,
        chaddr::16-binary,sname::512,file::size(128)-binary,99::8,130::8,83::8,99::8,options::binary>>) do
      decoded_options = decode_options(options,@opts)
      %Packet{msg_type: decoded_options[:message_type], requested_ip: decoded_options[:requested_ip_address] || {0,0,0,0}, op: op,
       htype: htype, hlen: hlen, hops: hops, xid: xid, secs: secs, flags: flags, 
       ciaddr: ip_address(:tuple,ciaddr),yiaddr: ip_address(:tuple,yiaddr),siaddr: ip_address(:tuple,siaddr),giaddr: ip_address(:tuple,giaddr),chaddr: hw_address(:tuple,chaddr),
       sname: sname, file: file, options: decoded_options}
    end

    defp decode_options(<<0::8,rest::binary>>,opts), do: decode_options(rest,opts)
    defp decode_options(<<255::8,_::binary>>,_opts), do: %{}
    defp decode_options(<<op::8,len::8,value::size(len)-binary,rest::binary>>,opts), do:
      Enum.into([{opts[op],dec_opt_val(opt_type(opts[op]), value)}],decode_options(rest,opts))

    def encode_packet(packet) do
      encoded_options = encode_options(packet.options,@opts_id)
      file = String.ljust(packet.file,128,0)
      <<packet.op::8,packet.htype::8,packet.hlen::8,packet.hops::8, packet.xid::32,packet.secs::16,packet.flags::16-big,
        ip_address(:bin,packet.ciaddr)::binary, ip_address(:bin,packet.yiaddr)::binary, ip_address(:bin,packet.siaddr)::binary, ip_address(:bin,packet.giaddr)::binary,
        hw_address(:bin,packet.chaddr)::binary,
        packet.sname::512,file::binary,<<99::8,130::8,83::8,99::8>>::binary,encoded_options::binary>>
    end

    defp encode_options(%{}=opts,opts_id), do: encode_options(Enum.to_list(opts),opts_id)
    defp encode_options([{name, val} | rest],opts_id) do
      opt_id = opts_id[name]
      opt_val = enc_opt_val(opt_type(name),val)
      <<opt_id::8,(byte_size(opt_val))::8,opt_val::binary,(encode_options(rest,opts_id))::binary>>
    end
    defp encode_options([],_), do: <<255::8>>

    defp ip_address(:tuple, <<a::8,b::8,c::8,d::8>>), do: {a,b,c,d}
    defp ip_address(:bin, {a,b,c,d}), do: <<a::8,b::8,c::8,d::8>>

    defp hw_address(:tuple, <<a::8,b::8,c::8,d::8,e::8,f::8,_::binary>>), do: {a,b,c,d,e,f}
    defp hw_address(:bin, {a,b,c,d,e,f}), do: <<a::8,b::8,c::8,d::8,e::8,f::8,0::80>>

    @opt_types %{subnet_mask: :ip_address,router: :ip_address,dns_server: :ip_address,broadcast_address: :ip_address,requested_ip_address: :ip_address,server_id: :ip_address,time_offset: :quad_int,lease_time: :quad_int,renewal_time: :quad_int,rebinding_time: :quad_int,max_message_size: :word_int,host_name: :string,domain_name: :string,message_type: :message_type, vendor_opts: :encapsulated}
    defp opt_type(x), do: @opt_types[x] || :binary

    defp dec_opt_val(:ip_address,val), do: ip_address(:tuple,val)
    defp dec_opt_val(:quad_int,<<quad::32-big>>), do: quad
    defp dec_opt_val(:word_int,<<word::16-big>>), do: word
    defp dec_opt_val(:string,val), do: val
    defp dec_opt_val(:message_type,<<1::8>>), do: :discover
    defp dec_opt_val(:message_type,<<2::8>>), do: :offer
    defp dec_opt_val(:message_type,<<3::8>>), do: :request
    defp dec_opt_val(:message_type,<<4::8>>), do: :decline
    defp dec_opt_val(:message_type,<<5::8>>), do: :ack
    defp dec_opt_val(:message_type,<<6::8>>), do: :nak
    defp dec_opt_val(:message_type,<<7::8>>), do: :release
    defp dec_opt_val(:message_type,<<8::8>>), do: :inform
    defp dec_opt_val(:encapsulated,val), do: decode_options(val,@vendor_opts)
    defp dec_opt_val(:binary,val), do: val
    defp dec_opt_val(nil,val), do: val

    defp enc_opt_val(:ip_address,val), do: ip_address(:bin,val)
    defp enc_opt_val(:quad_int,val), do: <<val::32-big>>
    defp enc_opt_val(:word_int,val), do: <<val::16-big>>
    defp enc_opt_val(:string,val), do: val
    defp enc_opt_val(:message_type,:discover), do: <<1::8>>
    defp enc_opt_val(:message_type,:offer), do: <<2::8>>
    defp enc_opt_val(:message_type,:request), do: <<3::8>>
    defp enc_opt_val(:message_type,:decline), do: <<4::8>>
    defp enc_opt_val(:message_type,:ack), do: <<5::8>>
    defp enc_opt_val(:message_type,:nak), do: <<6::8>>
    defp enc_opt_val(:message_type,:release), do: <<7::8>>
    defp enc_opt_val(:message_type,:inform), do: <<8::8>>
    defp enc_opt_val(:encapsulated,opts), do: encode_options(opts,@vendor_opts_id)
    defp enc_opt_val(:binary,val), do: val
    defp enc_opt_val(nil,val), do: val
  end
  defmodule Server do
    use GenServer
    def start_link(ip), do: GenServer.start_link(__MODULE__,ip)
    def init({a,b,c,_}=ip) do
      {:ok,sock} = :gen_udp.open(67, [:binary, :inet, broadcast: true, reuseaddr: true])
      {:ok,%{sock: sock, srv_ip: ip, broadcast: {a,b,c,255}}}
    end

    def handle_info({:udp,sock,_ip,68,bin},%{sock: sock}=s) do
      packet = Packet.decode_packet(bin)
      IO.puts "receive DHCP #{inspect(packet, pretty: true, limit: :infinity)}\n\n\n"
      case packet do
        %{msg_type: :discover,options: %{class_id: "PXEClient:"<>_}}-> #PXEBoot, return PXE message
          send_packet(offer_pxe_packet(packet.xid,Lease.get(packet,s),s),s)
        %{msg_type: :discover}->
          send_packet(offer_packet(packet.xid,Lease.get(packet,s),s),s)
        %{msg_type: :request,requested_ip: req_ip, ciaddr: ciaddr}->
          case Lease.get(packet,s) do
            %{ip_addr: ip}=lease when ip == req_ip or (req_ip == {0,0,0,0} and ip == ciaddr)-> 
              send_packet(ack_packet(packet.xid,lease,s),s)
            _->
              send_packet(nak_packet(packet,s),s)
          end
      end
      {:noreply,s}
    end
    def handle_info(_info,s), do: {:noreply,s}

    defp offer_packet(xid,lease_info,%{}), do:
      %Packet{ msg_type: :offer, op: 2, htype: 1, hlen: 6, xid: xid, yiaddr: lease_info.ip_addr, siaddr: Conf.srv_ip,
         chaddr: lease_info.chaddr, options: Enum.into([message_type: :offer, server_id: Conf.srv_ip],lease_info.options) }
    defp offer_pxe_packet(xid,lease_info,%{}), do:
      %Packet{ msg_type: :offer, op: 2, htype: 1, hlen: 6, xid: xid, yiaddr: lease_info.ip_addr, siaddr: Conf.srv_ip, file: "undionly.kpxe",
         chaddr: lease_info.chaddr, options: Enum.into([ vendor_opts: %{
             pxe_boot_servers: <<0::16,1,192,168,56,1>> #, pxe_boot_menus: <<0::16,8,"KBRW_PXE"::binary>>
           },class_id: "PXEClient",message_type: :offer, server_id: Conf.srv_ip], lease_info.options) }
    defp ack_packet(xid,lease_info,%{}), do:
      %Packet{ msg_type: :ack, op: 2, htype: 1, hlen: 6, xid: xid, yiaddr: lease_info.ip_addr, siaddr: Conf.srv_ip,
        chaddr: lease_info.chaddr, options: Enum.into([message_type: :ack, server_id: Conf.srv_ip],lease_info.options) }
    defp nak_packet(packet,%{}), do:
      %Packet{ msg_type: :nak, op: 2, htype: 1, hlen: 6, xid: packet.xid, siaddr: Conf.srv_ip, chaddr: packet.chaddr,
         options: %{message_type: :nak, server_id: Conf.srv_ip}}

    use Bitwise
    defp send_packet(packet,%{sock: sock}) do
      enc_packet = Packet.encode_packet(packet)
      dest = dest_addr(packet)
      IO.puts "send DHCP to #{inspect dest} #{inspect(packet, pretty: true, limit: :infinity)}\n\n\n"
      case :gen_udp.send(sock, dest, 68, enc_packet) do
        :ok -> :ok
        {:error, reason} when reason in [:ehostdown,:ehostunreach]->
          IO.puts("DHCP send to #{inspect dest} got #{inspect reason}, swith to broadcast")
          :gen_udp.send(sock, Conf.broadcast, 68, enc_packet)
      end
    end
    defp dest_addr(%{flags: flags}) when band(flags,0x8000) != 0, do: Conf.broadcast
    defp dest_addr(%{msg_type: msg_type}) when msg_type in [:offer,:nak], do: Conf.broadcast
    defp dest_addr(%{ciaddr: {0,0,0,0}}), do: Conf.broadcast
    defp dest_addr(%{ciaddr: ciaddr}), do: ciaddr
  end
end

{:ok,_pid} = :tftp.start(debug: :brief, udp: [ip: Conf.srv_ip], callback: {'.*',PXE.TFTP,[]})
_pid = PXE.HTTP.start_link(Conf.srv_ip,80)
{:ok,_pid} = PXE.DHCP.Server.start_link(Conf.srv_ip)
IO.puts "start HTTP cloudconfig serving on #{inspect Conf.srv_ip} port #{80}"
IO.puts "start DHCP on #{inspect Conf.srv_ip}"
receive do end
