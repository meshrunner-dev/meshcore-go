#include <RNG.h>

// Link stubs for the rweather/Crypto RNG: the generator never touches
// it (identities come from the vendored orlp ed25519, deterministically
// seeded), but Ed25519.cpp references the global object.
RNGClass::RNGClass() {}
RNGClass::~RNGClass() {}
void RNGClass::rand(uint8_t*, size_t) {}
bool RNGClass::available(size_t) const { return false; }
void RNGClass::stir(const uint8_t*, size_t, unsigned int) {}
void RNGClass::save() {}
void RNGClass::loop() {}
void RNGClass::destroy() {}
void RNGClass::begin(const char*) {}
void RNGClass::addNoiseSource(NoiseSource&) {}
void RNGClass::setAutoSaveTime(uint16_t) {}
RNGClass RNG;
