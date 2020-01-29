#!/usr/bin/expect -f
set mail [lindex $argv 0];
set pass [lindex $argv 1];
catch {exec nordvpn logout}
spawn nordvpn login
expect "Email / Username: "
send -- "$mail\r"
expect "Password: "
send -- "$pass\r"
expect eof

exec nordvpn c
set timeout -1
