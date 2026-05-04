.PHONY: dev api dashboard simulate reset install help

help:
	@echo "ADWatchdog Lite — make targets"
	@echo "  make install     install python + node deps"
	@echo "  make dev         run api (8000) + dashboard (5173) together"
	@echo "  make api         run only the FastAPI backend"
	@echo "  make dashboard   run only the Vite dev server"
	@echo "  make simulate A=A1   run one scenario from the CLI (no UI needed)"
	@echo "  make reset       wipe lab.db and runbooks/output"

install:
	pip install -r requirements.txt
	cd dashboard && npm install

api:
	uvicorn api.main:app --reload --port 8000

dashboard:
	cd dashboard && npm run dev

dev:
	@echo "Starting API on :8000 and dashboard on :5173 (Ctrl-C to stop both)"
	@trap 'kill 0' INT TERM EXIT; \
	  uvicorn api.main:app --port 8000 & \
	  (cd dashboard && npm run dev) & \
	  wait

A ?= A1
simulate:
	python -m simulator.cli $(A)

reset:
	rm -f lab.db
	rm -f runbooks/output/*.md
	@echo "lab.db cleared, runbook outputs removed."
