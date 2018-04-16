#!/bin/sh

set -e

parse_cmdline() {
  local word quoted key value
  local callback=$1
  set -- $(cat /proc/cmdline)
  for word; do
      if [ -n "$quoted" ]; then
          value="$value $word"
      else
          case $word in
              *=*)
                  key=${word%%=*}
                  value=${word#*=}
  
  		if [[ $value =~ ^[\"\'] ]]; then
                      quoted=${value:0:1}
                  fi
                  ;;
              '#'*)
                  break
                  ;;
              *)
                  key=$word
                  ;;
          esac
      fi
  
      if [ -n "$quoted" ]; then
          if [[ $value =~ "$quoted"$ ]] ; then
              unset quoted
          else
              continue
          fi
      fi
      if [[ $value =~ ^[\"\'] ]] && [[ $value =~ "${value:0:1}"$ ]] ; then
          value=${value#?}
  	  value=${value%?}
      fi
  
      "$callback" "$key" "$value"
      unset key value
  done
}

rm -Rf /sysroot
mkdir /sysroot
mount -t tmpfs -o size=256M tmpfs /sysroot
cp -R /VERSION /bin /lib /usr /var /tmp /lib64 /init /root /etc /sbin /run /sysroot/
mkdir -p /sysroot/dev /sysroot/proc /sysroot/sys
rm /usr/bin/init /sysroot/usr/bin/init
cp /init /sysroot/usr/bin/init
cp /init /usr/bin/init
rm -f /sysroot/usr/lib/systemd/system/default.target
#ln -s multi-user.target /sysroot/usr/lib/systemd/system/default.target 
#ln -s emergency.target /sysroot/usr/lib/systemd/system/default.target
ln -s /etc/systemd/system/arcore.target /sysroot/usr/lib/systemd/system/default.target

DOINSTALL=false
for_each_cmdline() {
    case $1 in
        arcore.fs)
	    curl --retry-connrefused --retry 60 --retry-delay 1 "$2" | tar -xvzC /sysroot -f -
            ;;
        arcore.install)
	    DOINSTALL=true
            ;;
        *)
            # ignore other cmdline
            ;;
    esac
}
parse_cmdline for_each_cmdline

if [ "$DOINSTALL" = "true" ] && [ -f /sysroot/install.sh ]; then
  bash /sysroot/install.sh | bash /usr/bin/arcore_alert.sh
fi

## network has been configured in order to get rootfs overlay
## so remove all the kernel modules for net devices
## in order to make a clean udev device configuration
for d in $(for p in /sys/class/net/*/device/driver; do echo $(basename $(readlink -f $p)); done | sort | uniq); do
modprobe -r $d
done
touch /oksysroot
