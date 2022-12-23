.PHONY: clean build publish

build: clean
	python -m pip install --upgrade --quiet setuptools wheel twine
	python -m build

build_publish: build
	python -m twine check dist/*
	python -m twine upload dist/*

publish:
	python -m twine check dist/*
	python -m twine upload dist/*

clean:
	rm -r build dist *.egg-info || true
