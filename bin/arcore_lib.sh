#!/bin/bash

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
