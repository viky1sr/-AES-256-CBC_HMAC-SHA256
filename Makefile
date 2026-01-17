SHELL := /bin/bash

PORT ?= 8000
SERVER_CMD ?= php server.php start
CLOUDFLARED ?= ./cloudflared
ORIGIN ?= http://localhost:$(PORT)

LOG_DIR := .run
SERVER_LOG := $(LOG_DIR)/server.log
TUNNEL_LOG := $(LOG_DIR)/tunnel.log
SERVER_PID := $(LOG_DIR)/server.pid
TUNNEL_PID := $(LOG_DIR)/tunnel.pid

.PHONY: start start-server start-tunnel stop status logs clean

start:
	@mkdir -p $(LOG_DIR)
	@$(MAKE) stop
	@$(MAKE) start-server
	@$(MAKE) start-tunnel

start-server:
	@mkdir -p $(LOG_DIR)
	@nohup bash -lc "$(SERVER_CMD)" > "$(SERVER_LOG)" 2>&1 & echo $$! > "$(SERVER_PID)"
	@sleep 1
	@echo "Server PID: $$(cat $(SERVER_PID))"
	@echo "Server: http://127.0.0.1:$(PORT)"
	@curl -I "http://127.0.0.1:$(PORT)" 2>/dev/null | head -n 5 || true

start-tunnel:
	@mkdir -p $(LOG_DIR)
	@echo
	@echo "Starting Cloudflare Tunnel (URL will appear below):"
	@stdbuf -oL -eL $(CLOUDFLARED) tunnel --url $(ORIGIN) 2>&1 \
		| tee -a "$(TUNNEL_LOG)" \
		& echo $$! > "$(TUNNEL_PID)"
	@sleep 1
	@echo "Tunnel PID: $$(cat $(TUNNEL_PID))"

stop:
	@set +e; \
	maybe_kill() { \
		f="$$1"; want="$$2"; \
		if [ -f "$$f" ] && [ -s "$$f" ]; then \
			p=$$(cat "$$f"); \
			if kill -0 $$p 2>/dev/null; then \
				cmd=$$(ps -p $$p -o args= 2>/dev/null); \
				echo "$$cmd" | grep -q "$$want" && kill $$p 2>/dev/null || true; \
			fi; \
			rm -f "$$f"; \
		fi; \
	}; \
	maybe_kill "$(TUNNEL_PID)" "cloudflared tunnel"; \
	maybe_kill "$(SERVER_PID)" "php server.php start"; \
	echo "Stopped."

status:
	@echo "== Listening on :$(PORT) =="
	@ss -lntp | grep ":$(PORT)" || true
	@echo
	@echo "== Processes =="
	@ps aux | egrep "cloudflared tunnel|php server.php start" | egrep -v egrep || true

logs:
	@echo "== server log =="
	@tail -n 80 "$(SERVER_LOG)" 2>/dev/null || true
	@echo
	@echo "== tunnel log =="
	@tail -n 120 "$(TUNNEL_LOG)" 2>/dev/null || true

clean:
	@rm -rf "$(LOG_DIR)"
