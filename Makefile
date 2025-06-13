lint:
	isort --check-only --diff .
	flake8 .
	pyright .

test:
	pytest -v
