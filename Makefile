lint:
	isort --check-only --diff .
	flake8 .
	pyright .

test:
	pytest -v --cov=encryptedcookie --cov-report=html --cov-report=term
