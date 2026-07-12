PWSH ?= pwsh

.PHONY: bootstrap format format-check test lint build pester verify

bootstrap:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command bootstrap

format:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command format

format-check:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command format-check

test:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command test

lint:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command lint

build:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command build

pester:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command pester

verify:
	$(PWSH) -NoProfile -File scripts/dev.ps1 -Command verify
