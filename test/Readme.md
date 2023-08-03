## run test

make test


## pass args to pytest

make test pytest=-s
make test pytest='-k echo'


## just run test without process

1. run process in netns

```
ip netns exec xudp bash
./test/bin/test_echo
```

2. run pytest without process

```
make test pytest='-k echo --noproc'
```

