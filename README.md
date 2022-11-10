# Installing project

## Clone project

```bash
    git clone git@bitbucket.org:d3f1g0/???.git
```

## Build project for Developer PC

```bash
    meson setup build --buildtype=debug
    ninja -C build
```


## Build project for Emak

```bash
    meson setup dist --cross-file emak.ini
    ninja -C dist
```
