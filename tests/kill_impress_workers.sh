pids="$(ps aux | grep -v grep | grep impress | awk '{ print $2; }')"
if [ -n "$pids" ]; then
  echo $pids
  sudo kill -9 $pids
fi
