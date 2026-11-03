# DEPLOY: Foundry Field Guide microsite

Served at https://saleemyousaf.co.uk/foundry/ as its own repo, the Depth pattern.
All files are at the repo root (no dist folder), so GitHub Pages serves them
directly. Every path inside the pages is relative, so the site works at that
subpath with no edits.

## Part 1, the microsite repo (this bundle)
1. Create a new GitHub repo named exactly  foundry
2. Upload every file in this bundle to the repo ROOT, keeping the fonts/ folder:
   index.html, attack-paths.html, app.js, style.css, favicon.svg, og-foundry.png,
   _headers, .nojekyll, README.md, DEPLOY.md, and fonts/ (6 files).
   IMPORTANT: upload the FILES to the root. Do not drag a folder named foundry-site
   or dist into the repo, that would nest them and break the paths.
3. Settings, Pages: Source = Deploy from a branch, Branch = main, Folder = / (root).
4. No CNAME in this repo. The apex domain is set on your main user-site repo, and
   project repos are served automatically at saleemyousaf.co.uk/<repo-name>.
5. Wait for Pages to publish, then open https://saleemyousaf.co.uk/foundry/

Note: .nojekyll stops Jekyll touching the files (needed for the fonts folder).
GitHub Pages ignores _headers (it is a Cloudflare/Netlify file); the CSP meta tag
is the live policy and is enough. If you ever front it with Cloudflare, _headers
adds frame-ancestors and the security headers.

## SEO already wired into the pages (both)
- canonical to the live URL
- og:url, og:image (og-foundry.png), og:site_name, full Twitter card
- JSON-LD TechArticle with author Saleem Yousaf and sameAs to LinkedIn, GitHub and
  cyberspartans.co.uk (entity signal), publisher and mainEntityOfPage
- meta keywords
- the microsite already links back to saleemyousaf.co.uk and cyberspartans.co.uk
IF the final path is not /foundry, tell me and I will repoint the canonical and
og:url, they must match the live URL or Google ignores them.

## Part 2, main-site tweaks for backlinks and indexing (snippets)
I do not have your current main repo in this turn, so these are paste-in snippets.
Send me the current main repo and I will return exact updated files instead.

### A) Projects page: swap the PDF card for the interactive microsite card
In projects/index.html, replace the existing "Foundry Attack Paths: Penetration
Test Field Guide" card (the one linking to the PDF) with this, so Projects points
at the richer interactive site (the PDF is still available via print-to-PDF inside
it and via the article):

      <a href="/foundry/" class="project-card amber" data-cat="ai">
        <div class="pc-eyebrow amber">// Interactive Microsite</div>
        <div class="pc-title">Foundry Field Guide: Deploy Microsoft Foundry Securely</div>
        <div class="pc-body">An interactive field guide to deploying Microsoft Foundry so one failed control is not a breach. Trace a threat through the guardrails, follow the deployment step by step, and explore fifteen attack paths with test cases and pass criteria. Static, no tracking, print to PDF built in.</div>
        <div class="pc-tags">
          <span class="pc-tag amber">Microsoft Foundry</span>
          <span class="pc-tag amber">AI Agents</span>
          <span class="pc-tag amber">Guardrails</span>
          <span class="pc-tag amber">15 Attack Paths</span>
        </div>
        <div class="pc-link">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
          Open the interactive site
        </div>
      </a>

### B) Articles page: add a backlink from the attack-paths article to the microsite
In articles/azure-ai-foundry-attack-paths/index.html, near the download button,
add a line so the written article funnels readers to the interactive version
(internal backlink, both ways):

    <p>Prefer it interactive? Explore the same material, trace a threat through the guardrails and step through each path, in the <a href="/foundry/">Foundry Field Guide</a>.</p>

### C) Main sitemap.xml: add the two microsite URLs
  <url>
    <loc>https://saleemyousaf.co.uk/foundry/</loc>
    <lastmod>2026-11-03</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://saleemyousaf.co.uk/foundry/attack-paths.html</loc>
    <lastmod>2026-11-03</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>

## Part 3, Google indexing (your step)
1. Deploy the microsite and confirm https://saleemyousaf.co.uk/foundry/ loads.
2. Apply the three main-site snippets so there are internal links pointing at the
   microsite (Projects card, article link) and the sitemap lists it.
3. Search Console: URL Inspection on https://saleemyousaf.co.uk/foundry/ and on
   /foundry/attack-paths.html, Request Indexing for each.
4. Re-submit the main sitemap.xml so Google picks up the new URLs.
5. Share the links on LinkedIn and Medium if you want external signals; the og
   card and Twitter card will render a proper preview.

## What about the old article and PDF?
The microsite is the primary interactive home now. The written attack-paths
article stays (good for search, and it now links into the microsite via snippet
B). The standalone PDF (articles/ai-foundry/...) is redundant with the built-in
print-to-PDF, but harmless; leave it or remove it, your call.
