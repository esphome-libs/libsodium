# libsodium-esphome

This is a port of [libsodium](https://github.com/jedisct1/libsodium) - A modern, portable, easy to use crypto library.

We use libsodium 1.0.21 as the base (see libsodium submodule) with some simple patches in port/port_include to make the library compile with the [platformio](https://platformio.org/) and [ESP-IDF](https://github.com/espressif/esp-idf) build systems.

Only a subset of libsodium is compiled, namely the cryptographic primitives required for [noise-c](https://github.com/esphome/noise-c/).

## Plain CMake

Outside of ESP-IDF, `CMakeLists.txt` defines an ordinary static library target, so any CMake project can consume it directly:

```cmake
add_subdirectory(path/to/libsodium-esphome)
target_link_libraries(my_target PRIVATE esphome::sodium)
```

The target is named `sodium`, with `esphome::sodium` as an alias. Include directories, `CONFIGURED=1` and the warning suppressions are all carried on the target.

libsodium is licensed under the [ISC License](https://github.com/jedisct1/libsodium#license)
