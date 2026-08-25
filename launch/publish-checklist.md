# npm publish + launch checklist

Ordered by the sequence from the launch plan. Every item is a single action; bracket the ones you want to automate and the ones you want to do yourself. Nothing here should take more than 10 minutes of your time unless marked otherwise.

## T-14 days — pre-launch

- [ ] Create a GitHub org and repo at `github.com/jourdanlabs/vantage` (or whatever the final handle is). Push the current code, specs, and benchmarks.
- [ ] Enable GitHub Actions on the repo. Trigger `benchmark-weekly.yml` manually once via `gh workflow run benchmark-weekly.yml` to populate Semgrep / SonarQube / CodeQL v2 numbers on the leaderboard.
- [ ] Send the four maintainer heads-up emails from `launch/maintainer-emails.md`. Fill in the date placeholders with your real planned publication date.
- [ ] Register `benchmark.vantage.dev` (or equivalent) and prep DNS.

## T-10 days

- [ ] Deploy the Astro site to Cloudflare Pages or Vercel. From `sites/leaderboard/`, `npx astro build` then push `dist/` to your hosting. Both Cloudflare and Vercel support automatic builds from GitHub push — configure that instead if you prefer. Expected time: 30 minutes.
- [ ] Point `benchmark.vantage.dev` DNS at the deployment. Confirm the live site renders the current results, the methodology page, and the per-tool pages.
- [ ] Run the receipts hunt against 3–5 additional repos (Ghost, Strapi, Directus, Parse Server) for extra launch-day ammunition. Use `benchmarks/receipts-hunt.js` as the starting point; expand the corpus list. Save the findings to `launch/receipts-extras.md`.
- [ ] Record the 90-second demo video per `launch/demo-script.md`. Save as MP4. Upload to YouTube as an unlisted video (we'll make it public on launch day). Also export a 30-second GIF for Twitter.

## T-5 days

- [ ] npm publish dry run:
  ```bash
  npm whoami   # confirm you're logged in
  npm pack --dry-run   # preview what goes in the tarball
  ```
  Inspect the output. Confirm it includes `dist/`, `bin/`, `hooks/`, `README.md`, `LICENSE`, and does NOT include `node_modules`, `src/main/`, `src/renderer/`, `src/preload/`, or the test fixtures.
- [ ] Test the package end-to-end in a fresh directory:
  ```bash
  mkdir /tmp/vantage-test && cd /tmp/vantage-test
  npm init -y
  npm install $(npm pack /path/to/vantage-repo)
  npx vantage analyze .
  npx vantage-mcp < /dev/null   # should start stdio server; Ctrl+C after a second
  ```
  Both should run cleanly. If anything fails, fix before publishing.
- [ ] Tag the release locally: `git tag v1.0.0 && git push --tags`.
- [ ] Draft the GitHub release notes. Copy the launch blog post content as a starting point.

## T-1 day — launch eve

- [ ] Final check: pull the live leaderboard site and confirm Semgrep / SonarQube / CodeQL numbers are populated (not stale or null). If anything shows "pending rerun," manually trigger the workflow one more time.
- [ ] Pre-draft the HN / Twitter / LinkedIn posts. Keep them short. Lead with the benchmark URL, not VANTAGE.
- [ ] Write the follow-up DMs to specific people you want to see the launch — researchers, tool authors, journalists who cover security tooling. Plan to send these day-of, after the launch goes live.

## Launch day

Ship in this order. The delay between steps is intentional — earlier steps should be well-indexed before later ones drive traffic.

- [ ] 08:00 UTC: `npm publish` for the `vantage` package. Verify install works globally (`npm install -g vantage` on a fresh machine, `vantage --help` prints the expected output).
- [ ] 08:30 UTC: Publish the blog post on your site. If you don't have a site, use GitHub's blog-style README on a separate `vantage-launch` repo, or post it as a Gist. Wherever it lives, the URL needs to be stable.
- [ ] 09:00 UTC: Make the YouTube demo video public. Tweet it with the blog post link.
- [ ] 10:00 UTC: Submit to Hacker News. Headline format: "Open benchmark: static analysis tools ranked on OWASP corpora (VANTAGE, Semgrep, SonarQube, CodeQL)". Ideally, have someone other than you submit — organic look matters. You can vouch for the comment thread.
- [ ] 10:30 UTC: Post to /r/programming, /r/netsec, /r/javascript. Same headline. Adapt to subreddit conventions.
- [ ] 11:00 UTC: Send individual DMs to the people you pre-drafted. These are the ones who'll seed good commentary early.
- [ ] Throughout the day: respond to every HN comment, every GitHub issue, every DM. Especially respond to critique — don't argue, incorporate or explain.

## T+1 day

- [ ] Publish a "launch retrospective" tweet thread with the numbers: npm installs, HN rank peak, GitHub stars, leaderboard traffic. Transparent post-mortems make the product look more credible, not less.
- [ ] Merge all the good-faith PRs from the first 24 hours. Ask people to retry anything you couldn't get to.
- [ ] If any maintainers from Semgrep / Sonar / CodeQL engaged, publicly thank them and incorporate their feedback.

## T+7 days

- [ ] Publish the first "weekly VANTAGE digest" — 3–5 interesting bugs found across OSS that week, each with a short writeup and a link to the `generate_fix` output. Build the habit.
- [ ] Begin the NEBULA v1.1 interprocedural work. Ship it when it's ready; aim for 6–8 weeks out.

## Notes on monetization

v1.0 source is public and proprietary (not open source). No premium tier, no cloud product at launch. Revenue lives in the future:

- **Hosted VANTAGE** — a SaaS that runs VANTAGE weekly against your codebase and sends a findings digest. Competes with Snyk, not GitHub Advanced Security. Needs customer-zero before design.
- **VANTAGE for Enterprise** — on-prem deploy with private source/sink catalogs, integration with enterprise SSO / SCIM / audit. Standard open-core play.
- **The leaderboard** stays free forever. Every monetization move has to avoid the perception that the benchmark is a loss-leader for paid features. That reputation is the product's spine.

Don't launch any of the monetization threads at the same time as v1.0. Do the launch; build mindshare; then — maybe 6 months out — do the paid tier on top. If you launch both at once, the "referee" narrative collapses into "vendor selling stuff."

## The one thing you should not do

Do not respond to critique by getting defensive. If someone posts "your benchmark is unfair because X," the correct reply is: "That's a fair point — here's why we made that choice, and here's what would change it." Not: "You're wrong, here's why." The product's entire credibility story is "we publish the rules and update them when the community has a better argument." Prove it on launch day.
