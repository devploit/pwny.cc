# Misc

### Python shell beautifier

```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

### Upgrade Full TTY - PTY Module

```bash
$ python -c 'import pty; pty.spawn("/bin/bash")'
user@remote:$ ^Z #(background)

root@kali:$ stty -a | head -n1 | cut -d ';' -f 2-3 | cut -b2- | sed 's/; /\n/' #(get ROWS and COLS)
root@kali:$ stty raw -echo; fg

user@remote:$ reset
user@remote:$ stty rows ${ROWS} cols ${COLS}
user@remote:$ export TERM=xterm #(or xterm-color or xterm-256color)
```

