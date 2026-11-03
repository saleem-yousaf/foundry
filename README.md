# Foundry Field Guide

An interactive, vendor-neutral field guide to deploying Microsoft Foundry
(formerly Azure AI Foundry) securely. Two pages:

- index.html : the guide. What Foundry is, an interactive threat explorer,
  landing zones and hybrid, step-by-step deployment, the threat library, layered
  guardrails, rogue-agent and unapproved-training controls, operate and detect,
  and a downloadable checklist.
- attack-paths.html : fifteen attack paths (AP01 to AP15) with reasoning, test
  cases, pass criteria and effort, for scoping a penetration test. Print to PDF
  built in (each path starts on a new page, light theme).

Static, no tracking, no backend, nothing leaves the browser. Strict Content
Security Policy in a meta tag (no inline script or style), so it is safe on any
host. Self-hosted IBM Plex fonts.

Served at https://saleemyousaf.co.uk/foundry/
