PYTHON_IMAGE		?= wpengine/python
REQUIREMENTS_FILES	:= requirements requirements-dev

.PHONY: clean package publish test update-all-requirements typos $(addsuffix .txt, $(REQUIREMENTS_FILES)) docs/requirements.txt

test:
	pytest --cov=hvac tests/

clean:
	rm -rf dist hvac.egg-info

distclean: clean
	rm -rf build

package:
	python setup.py sdist bdist_wheel

typos:
	typos --format brief

# Note, we breakout the docs/requirements target separately since its not reasonable to use filesystem paths in target names
update-all-requirements: $(addprefix update-, $(REQUIREMENTS_FILES)) update-docs-requirements
update-docs-requirements:
	$(call pip-compile,docs/requirements)
update-%:
	$(call pip-compile,$(*))

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
