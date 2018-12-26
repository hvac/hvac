PYTHON_IMAGE	?= wpengine/python

.PHONY: clean package publish test update-all-reqs update-reqs update-parser-reqs update-dev-reqs update-docs-reqs version

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

update-reqs:
	$(call pip-compile,requirements)
update-parser-reqs:
	$(call pip-compile,requirements-parser)
update-dev-reqs:
	$(call pip-compile,requirements-dev)
update-docs-reqs:
	$(call pip-compile,docs/requirements)
update-all-reqs: update-reqs update-parser-reqs update-dev-reqs update-docs-reqs

define pip-compile
	@echo
	# Running pip-compile to update $(1).txt (using $(1).in)...
	@docker run \
		--rm \
		--volume $(PWD):/workspace \
		${PYTHON_IMAGE} \
			pip-compile --upgrade --output-file $(1).txt $(1).in
	@echo
	# Successfully compiled python $(1).txt (using $(1).in).
endef
