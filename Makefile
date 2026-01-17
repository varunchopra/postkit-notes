.PHONY: build up down clean lint format

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

clean:
	docker compose down -v

lint:
	uvx ruff check app/

format:
	uvx ruff format app/
