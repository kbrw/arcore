# Arcore OS

A Micro linux distribution with NO installation for an Immutable OS.

## Arcore Principle

Arcore is an INITRD OS, containing :
- runc
- busybox
- systemd

Which adds to the "Root" filesystem before bootup the content of a "tar.gz" file
given as a URL in a kernel command line parameter "arcore.fs".

In order to do that, Arcore needs network, this network setup is done with
systemd-networkd", with basic config in a kernel command line parameter
"arcore.net" (line break are encoded as `\\n`).

For example, if we boot it with IPXE (does not need hard disk install) : 

    set base-url http://myhost-configserver.com
    kernel ${base-url}/arcore-kernel initrd=arcore.img arcore.net="[Match]\\nName=eth0\\n[Network]\\nDHCP=ipv4" arcore.fs=${base-url}/hostfs.tgz arcore.alert=${base-url}/alert

In order to make the IPXE boot unique,
`http://myhost-configserver.com/hostfs.tgz` can send a different
"overlay file system" depending on the IP of the client.

- The OS root filesystem is a tmpfs in RAM, 
- The "arcore.fs" TGZ (see test/ipxe.exs hostfs function to see and example)
   - must contains `mount units` for mutable data (/var/containers, /var/journal)
   - must contains `service units` which runs containers with `runc`

## First Boot

In order to configure automatically the first time (partition, raid,
formatting, etc.), you can add the `arcore.install` kernel parameter.
With this param and if the file `/install.sh` is present inside the
`arcore.fs` tgz, then this script will be launch *BEFORE* the boot
process (during the initrd bootup before ).
