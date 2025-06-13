lint:
	isort --check-only --diff .
	flake8 .

test:
	pytest -v
