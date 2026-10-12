# Makefile for cncf-controls

CNCF_BASE_URL := https://raw.githubusercontent.com/cncf/contribute-site/main/docs/community/tags/security-and-compliance/publications/controls-catalog/catalog
DOWNLOAD_DIR  := download
VENV_DIR      := .venv
PYTHON        := python3
TRESTLE_WS    := trestle.ws

CNCF_YAML_FILES := \
	access.yaml \
	cnsc-nist-800-53-mapping.yaml \
	compute.yaml \
	deploy.yaml \
	develop.yaml \
	distribute.yaml \
	groups.yaml \
	metadata.yaml \
	securing-artefacts.yaml \
	securing-build-pipelines.yaml \
	securing-materials.yaml \
	securing-the-source-code.yaml \
	security-assurance.yaml \
	storage.yaml

CNCF_YAML_TARGETS := $(addprefix $(DOWNLOAD_DIR)/,$(CNCF_YAML_FILES))

.PHONY: venv install download-cncf-yaml clean-cncf-yaml clean-venv trestle-init clean-trestle build-catalog clean-catalog validate-catalog build-profile validate-profile update-readme all

## venv: Create a Python virtual environment and install requirements.txt
venv: $(VENV_DIR)/bin/activate

$(VENV_DIR)/bin/activate: requirements.txt
	$(PYTHON) -m venv $(VENV_DIR)
	$(VENV_DIR)/bin/pip install --upgrade pip
	$(VENV_DIR)/bin/pip install -r requirements.txt
	@touch $(VENV_DIR)/bin/activate
	@echo "Virtual environment ready. Activate with: source $(VENV_DIR)/bin/activate"

## install: Alias for venv
install: venv

## clean-venv: Remove the virtual environment
clean-venv:
	rm -rf $(VENV_DIR)

## download-cncf-yaml: Download all CNCF controls-catalog YAML files into $(DOWNLOAD_DIR)/
download-cncf-yaml: $(CNCF_YAML_TARGETS)
	@echo "All CNCF YAML files downloaded to $(DOWNLOAD_DIR)/"

$(DOWNLOAD_DIR)/%.yaml: | $(DOWNLOAD_DIR)
	@echo "Downloading $(@F) ..."
	curl --silent --show-error --fail --location \
		--output $@ \
		$(CNCF_BASE_URL)/$(@F)

$(DOWNLOAD_DIR):
	mkdir -p $(DOWNLOAD_DIR)

## clean-cncf-yaml: Remove downloaded CNCF YAML files
clean-cncf-yaml:
	rm -f $(CNCF_YAML_TARGETS)
	@rmdir $(DOWNLOAD_DIR) 2>/dev/null || true

## build-catalog: Build cncf-controls.json OSCAL catalog from downloaded YAML files
build-catalog: venv download-cncf-yaml trestle-init
	$(VENV_DIR)/bin/python scripts/build_catalog.py --download-dir $(DOWNLOAD_DIR) --trestle-ws $(TRESTLE_WS)

## clean-catalog: Remove the generated OSCAL catalog from the trestle workspace
clean-catalog:
	rm -rf $(TRESTLE_WS)/catalogs/cncf-controls

## validate-catalog: Validate the OSCAL catalog with trestle
validate-catalog: build-catalog
	cd $(TRESTLE_WS) && ../$(VENV_DIR)/bin/trestle validate --type catalog --name cncf-controls

## build-profile: Build the generic cncf-repo OSCAL profile
build-profile: build-catalog
	$(VENV_DIR)/bin/python scripts/build_profile.py --trestle-ws $(TRESTLE_WS)

## validate-profile: Validate the cncf-repo profile with trestle
validate-profile: build-profile
	cd $(TRESTLE_WS) && ../$(VENV_DIR)/bin/trestle validate --type profile --name cncf-repo

## update-readme: Regenerate the Mermaid chart and controls table in README.md
update-readme: validate-profile
	$(VENV_DIR)/bin/python scripts/update_readme.py --catalog $(TRESTLE_WS)/catalogs/cncf-controls/catalog.json --readme README.md

## all: Run all steps — download, build catalog, validate, update README
all: update-readme

## trestle-init: Create trestle.ws workspace directory and initialize it with trestle
trestle-init: venv
	mkdir -p $(TRESTLE_WS)
	cd $(TRESTLE_WS) && ../$(VENV_DIR)/bin/trestle init

## clean-trestle: Remove the trestle workspace directory
clean-trestle:
	rm -rf $(TRESTLE_WS)

## clean: Remove venv, downloaded YAML files, and trestle workspace
clean: clean-venv clean-cncf-yaml clean-trestle clean-catalog

## help: Show this help message
help:
	@grep -E '^## ' Makefile | sed 's/^## /  /'

.DEFAULT_GOAL := help
