<!--
  This pull request template is synced from puppetlabs/pdk-templates
  (moduleroot/.github/PULL_REQUEST_TEMPLATE.md.erb). Do not edit it directly in a
  module repo -- changes are overwritten on the next `pdk update`. To customize it
  for a single module, opt out with `.github/PULL_REQUEST_TEMPLATE.md: unmanaged: true`
  in the module's `.sync.yml` and maintain a hand-written copy.
-->

## Summary

Describe what this change does and why. Keep the change scoped to the linked ticket;
flag any unrelated cleanup as a separate ticket/PR.

## Related ticket / issue

<!-- Link the driving Jira ticket (MODULES-*) using the structured spec template, a
     community/customer GitHub issue, or leave blank if there is nothing to link. -->
- Ticket / issue: MODULES-XXXX

## Required checklist

- [ ] Linked the driving ticket or issue above where one exists (a `MODULES-*` ticket via the structured spec template, or a GitHub issue).
- [ ] Coverage gate is green (or the baseline is preserved -- coverage was not reduced).
- [ ] Platform matrix is green -- the PR's CI checks below cover it, or link a recent nightly Litmus run if the supported-OS acceptance tests do not run on this PR.
- [ ] `Co-Authored-By: Claude` trailer is present on the commits if this PR was AI-assisted.

## Review policy (outcome-based)

PRs are judged on outcomes, not line counts. Pick the lane that matches this change so
reviewers know what coverage to expect. See `CLAUDE.md` for the full policy.

- **Auto-merge** -- green CI required, no human review needed:
  dependabot bumps, modulesync / `pdk update` resync, `REFERENCE.md` regeneration, trivial doc fixes (typos, link fixes).
  Substantial doc changes -- e.g. a significant `README.md` rewrite -- still warrant a human review.
- **Single reviewer** -- green CI plus coverage preserved required:
  bug fixes, supported-platform additions, simple feature work.
- **Full review (2 or more reviewers)** -- green CI plus coverage plus senior sign-off:
  provider / type-API changes, security fixes, breaking changes.

This PR is (check one):

- [ ] Auto-merge
- [ ] Single reviewer
- [ ] Full review (2+)

## Additional context

<!-- Root cause, reproduction steps, and the reasoning behind the implementation, if applicable. -->
