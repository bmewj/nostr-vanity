nostr-vanity
============

C++ command-line program for finding vanity keys with a specific prefix.

## Usage

```bash
./nostr-vanity [prefix]
```

```
$ ./nostr-vanity hey

Searching for vanity pubkeys starting with "hey"

... represented as hex ...
  prefix to find (in hex) = be48000000000000
  prefix mask    (in hex) = fffe000000000000

Running search on 8 threads!

npub1heyq6fk0npk8kehsglzlx2sqhg... 3cf3fd4b42cc046e2d36b54c31bc2ecf47c5d848cb1d8c0e63708b8c5b95954d
npub1heyu3953m3gfrhfxgl8cm5g52v... 126a62c58548936ec02f0554a22ea65ac87756c78d484d74672bda894cdfbf6f
npub1hey90jmwxagcjaxk3an99ankqg... 10253dd519c81ffa5a2da16b5e32f8f509b6669759e9544723227c4a907d5d52
npub1heym9sh3dg66n08hwpypah6p9v... 18a915c63d408e1c977fa4355905530fd9634d267a91e1dea3bff7699401ac45
npub1heyr4rd463ec6hhpdxenjezflv... 9fa1abb5eb8776cff9c3661af6ce9c0b25355ee1560cb3a6924fdf10ee249904
npub1heys3hdcpwks4mrfplxrkve775... 23d7580e54cead25867e456469552945ece9ad761e2f5c61a8b07280f7bae4b4
npub1heytgjknesfkrd3en9xzcwwmc5... d31dc3d7e7b8d268c205bc13d7d18d0df4d39009c2f32aa1cc00d3180f76d28c
npub1heydmdgng9yqhn667xmsxll0hy... e1b1a7a852588795ef995bf1c0a62f4f379c0a688b96024f0ca9d90c9a19c54a
npub1hey27ehlzp53uqjlzmuxwcq0wc... a048f87dd023d234f3c9066d6bf1ace53fffb3e7a55c83e42241b1030848091f
```

It prints out all keys matching a given prefix along with their secret key in hex.

## Build

Project uses CMake to build. Make sure this is installed on your system.

```bash
git clone --recursive git@github.com:bmewj/nostr-vanity.git
mkdir build
cd build
cmake ..
make
```

