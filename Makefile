test: version
	tox

version:
	cp version hvac/version

clean:
	rm -rf dist hvac.egg-info

distclean: clean
	rm -rf build hvac/version .tox

package: clean version
	pip install wheel
	python setup.py sdist bdist_wheel

publish: package
	pip install twine
	twine upload dist/*

.PHONY: clean package publish test version
