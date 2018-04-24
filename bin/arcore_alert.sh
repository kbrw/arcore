. /usr/bin/arcore_lib.sh
ALERT=false
for_each_cmdline() {
    case $1 in
        arcore.alert)
	    ALERT="$2"
	    ;;
        *)
            # ignore other cmdline
            ;;
    esac
}
parse_cmdline for_each_cmdline

if [ "$ALERT" != "false" ]; then
  curl -XPOST --data-binary @- "$ALERT"
fi
