test: version
	tox

version:
	cp version hvac/version

clean:
	rm -rf dist hvac.egg-info

distclean: clean
	rm -rf build hvac/version .tox

package: version
	python setup.py sdist bdist_wheel

.PHONY: clean package publish test version
