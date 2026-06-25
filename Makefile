# Root Makefile — drive all 16 chapters.
#
#   make all          compile every chapter binary
#   make sign         compile + wrap each in a signed .app with embedded ES profile
#   make verify       check each .app for ES entitlement + hardened runtime
#   make clean        remove binaries and .app bundles
#   make list         show chapter -> target mapping
#
# Signing requires the ES provisioning profile. Pass its path once:
#   make sign PROFILE=~/Downloads/endptsec-dev.provisionprofile
#
# After signing, run a chapter (each is a long-running ES client; Ctrl-C to stop):
#   sudo ./01-hello-exec/hello-exec.app/Contents/MacOS/hello-exec

CHAPTERS := $(sort $(wildcard [0-9][0-9]-*))
SIGN_ID  ?= Apple Development: Douglas Mun (PABRCU3Y4G)
PROFILE  ?=
export SIGN_ID

# target name read from each chapter's own Makefile (handles ch11 codesign-monitor)
target = $(strip $(shell grep -E '^TARGET' $(1)/Makefile | head -1 | sed 's/.*=[[:space:]]*//'))
entfile = $(strip $(notdir $(wildcard $(1)/*.entitlements)))

.PHONY: all sign verify clean list

all:
	@for ch in $(CHAPTERS); do \
	  echo "== compile $$ch =="; \
	  $(MAKE) -C $$ch all || exit $$?; \
	done

sign: all
	@if [ -z "$(PROFILE)" ]; then \
	  echo "ERROR: pass PROFILE=/path/to/es.provisionprofile" >&2; exit 2; fi
	@for ch in $(CHAPTERS); do \
	  tgt=$$(grep -E '^TARGET' $$ch/Makefile | head -1 | sed 's/.*=[[:space:]]*//' | tr -d ' '); \
	  ent=$$(ls $$ch/*.entitlements | head -1); \
	  PROFILE="$(PROFILE)" SIGN_ID="$(SIGN_ID)" \
	    tools/package.sh "$$ch" "$$tgt" "$$ent" || exit $$?; \
	done

verify:
	@for ch in $(CHAPTERS); do \
	  tgt=$$(grep -E '^TARGET' $$ch/Makefile | head -1 | sed 's/.*=[[:space:]]*//' | tr -d ' '); \
	  tools/verify.sh "$$ch" "$$tgt"; \
	done

list:
	@for ch in $(CHAPTERS); do \
	  tgt=$$(grep -E '^TARGET' $$ch/Makefile | head -1 | sed 's/.*=[[:space:]]*//' | tr -d ' '); \
	  printf "%-20s -> %s\n" "$$ch" "$$tgt"; \
	done

clean:
	@for ch in $(CHAPTERS); do \
	  tgt=$$(grep -E '^TARGET' $$ch/Makefile | head -1 | sed 's/.*=[[:space:]]*//' | tr -d ' '); \
	  rm -rf "$$ch/$$tgt.app"; \
	  $(MAKE) -C $$ch clean >/dev/null 2>&1 || true; \
	done
	@echo "cleaned binaries and .app bundles"
