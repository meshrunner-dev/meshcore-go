#pragma once

// Minimal host-side Stream/Print, covering what the compiled reference
// sources use (Utils::printHex, Identity read/write/printTo). MeshCore's
// own test mocks are not used: they also mock SHA256/AES, which must
// stay real here.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define DEC 10
#define HEX 16

class Print {
public:
  virtual ~Print() {}
  virtual size_t write(uint8_t) { return 1; }
  virtual size_t write(const uint8_t* buf, size_t n) {
    size_t t = 0;
    for (size_t i = 0; i < n; i++) t += write(buf[i]);
    return t;
  }
  size_t write(const char* buf, size_t n) { return write((const uint8_t*)buf, n); }
  size_t print(char c) { return write((uint8_t)c); }
  size_t print(const char* s) { return s ? write((const uint8_t*)s, strlen(s)) : 0; }
  size_t println() { return write((uint8_t)'\n'); }
  size_t println(const char* s) { return print(s) + println(); }
};

class Stream : public Print {
public:
  virtual int available() { return 0; }
  virtual int read() { return -1; }
  virtual size_t readBytes(uint8_t*, size_t) { return 0; }
  size_t readBytes(char* buf, size_t n) { return readBytes((uint8_t*)buf, n); }
};
