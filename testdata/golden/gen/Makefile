# goldengen — builds the golden-vector generator against the MeshCore
# reference sources and the crypto libraries the firmware links.
#
# Driven by the repo-root Taskfile, which fetches the release sources:
#
#   task golden VERSION=1.17.1 SEED=42
#   task golden:all
#
# Direct use needs both variables:
#
#   make corpus MESHCORE=third_party/meshcore-1.17.1 VERSION=1.17.1 SEED=42

SEED ?= 42

ifndef MESHCORE
$(error MESHCORE must point at a MeshCore source tree — use `task golden VERSION=…`)
endif
ifndef VERSION
$(error VERSION (a MeshCore release, e.g. 1.17.1) is required — it names the corpus file)
endif

ARDUINOLIBS_REPO   = https://github.com/rweather/arduinolibs
ARDUINOLIBS_COMMIT = 37a76b8f7516568e1c575b6dc9268da1ccaac6b6
CRY = third_party/arduinolibs/libraries/Crypto

BIN = goldengen-$(VERSION)
OUT = ../mc-$(VERSION)-seed$(SEED).ndjson.gz

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wno-unused-variable
# The receiver's PATH-descriptor validation was added in firmware 1.17;
# MESHCORE_MINOR lets the transcribed receiver match the target version.
MC_MINOR  = $(shell echo $(VERSION) | cut -d. -f2)
INCLUDES  = -I$(CRY) -I$(MESHCORE)/src -I$(MESHCORE)/lib/ed25519 -Ishim -DMESHCORE_MINOR=$(MC_MINOR)

SRCS = main.cpp rng_stub.cpp \
  $(MESHCORE)/src/Packet.cpp \
  $(MESHCORE)/src/Identity.cpp \
  $(MESHCORE)/src/Utils.cpp \
  $(MESHCORE)/src/helpers/AdvertDataHelpers.cpp \
  $(CRY)/SHA256.cpp $(CRY)/SHA512.cpp \
  $(CRY)/AES128.cpp $(CRY)/AESCommon.cpp $(CRY)/BlockCipher.cpp \
  $(CRY)/Ed25519.cpp $(CRY)/Curve25519.cpp $(CRY)/BigNumberUtil.cpp \
  $(CRY)/Crypto.cpp $(CRY)/Hash.cpp \
  $(wildcard $(MESHCORE)/lib/ed25519/*.c)

$(BIN): $(CRY) $(SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(SRCS)

$(CRY):
	git clone $(ARDUINOLIBS_REPO) third_party/arduinolibs
	git -C third_party/arduinolibs checkout -q $(ARDUINOLIBS_COMMIT)

.PHONY: corpus coverage clean

corpus: $(BIN)
	./$(BIN) $(SEED) | gzip -9n > $(OUT)
	@gzip -cd $(OUT) | wc -l | xargs echo "$(OUT) records:"

# Branch coverage of the reference sources while generating — the
# objective "diverse enough" check. Expected gaps: display formatting
# (printHex/AdvertTimeHelper), Stream/storage serializers, the RNG and
# validatePrivateKey — none of them wire protocol.
coverage: $(CRY)
	$(CXX) $(CXXFLAGS) --coverage $(INCLUDES) -o $(BIN)-cov $(SRCS)
	./$(BIN)-cov $(SEED) > /dev/null
	@for f in Packet Identity Utils AdvertDataHelpers; do \
	  gcov -b $(BIN)-cov-$$f.gcno 2>/dev/null | grep -A3 "^File.*$$f.cpp'"; done
	@rm -f *.gcov

clean:
	rm -f goldengen-* *.gcno *.gcda *.gcov
