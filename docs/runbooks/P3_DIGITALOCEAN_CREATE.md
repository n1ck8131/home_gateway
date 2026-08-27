# P3 DigitalOcean create gate

Run `scripts/p3-digitalocean-plan.ps1 -PublicKeyPath <absolute .pub path> -WhatIf` to validate the selected public key and print a redacted checklist. The script makes no cloud request and performs no billable action.

Only after the controller's offline gate and a fresh owner approval may the owner create one UI Droplet: `ams3` (fallback `fra1`), Ubuntu 24.04 x64, Basic Regular $6, IPv6 and monitoring on, with backups, volumes and Marketplace images off. Initial SSH prefixes and the one observed AmneziaWG UDP port remain `pending-observation`; default-route SSH access is forbidden.
