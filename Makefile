generate-proof:
	python -m stark101

test-contract:
	ligo run test contracts/verifier_test.mligo

build-contract:
	ligo compile contract contracts/main.mligo > build/verifier.tz
