# Developer Certificate of Origin (DCO)

AegisGate Lens requires that every commit be signed off by its author.
This is the same DCO mechanism used by the Linux kernel and the
AegisGate Platform repo.

## Why we require DCO

The DCO attests that the contributor has the right to submit the code
under the project's Apache 2.0 license. It is a lightweight legal
mechanism that gives enterprise customers confidence in our supply
chain without requiring a heavyweight Contributor License Agreement
(CLA).

This is consistent with the AegisGate Platform repo's `DCO.md`
policy and is enforced identically in CI.

## How to sign off your commits

### One-time setup

Configure git with your real name and email (the email must match a
verified GitHub email):

```bash
git config --global user.name "Your Full Name"
git config --global user.email "you@example.com"
```

### Adding the sign-off to a commit

Add `-s` (or `--signoff`) to your `git commit` command:

```bash
git commit -s -m "Lens: fix banner severity tint for low-severity detections"
```

This appends the following line to the commit message:

```
Signed-off-by: Your Full Name <you@example.com>
```

### Amending an existing commit

If you forgot `-s`:

```bash
git commit --amend --signoff
```

### Multiple commits on a branch

For a branch with multiple commits that need sign-off:

```bash
# Rebase and sign each one interactively, OR:
git rebase --exec 'git commit --amend --no-edit --signoff' HEAD~N
```

Where `N` is the number of commits to rebase.

## What the DCO text says

By adding a `Signed-off-by:` trailer, you certify, per the Linux
kernel's DCO 1.1, that:

> (a) The contribution was created in whole or in part by me and I
>     have the right to submit it under the open source license
>     indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
>     of my knowledge, is covered under an appropriate open source
>     license and I have the right under that license to submit that
>     work with modifications, whether created in whole or in part
>     by me, under the same open source license (unless I am
>     permitted to submit under a different license), as indicated
>     in the file; or
>
> (c) The contribution was provided directly to me by some other
>     person who certified (a), (b) or (c) and I have not modified
>     it.
>
> (d) I understand and agree that this project and the contribution
>     are public and that a record of the contribution (including all
>     personal information I submit with it, including my sign-off) is
>     maintained indefinitely and may be redistributed consistent with
>     this project or the open source license(s) involved.

## CI enforcement

The CI workflow at `.github/workflows/governance.yml` runs a DCO
check on every push and every pull request. For pull requests, the
check is **strict** — every commit must have a Signed-off-by line,
and the PR will be blocked from merging until it does. For pushes
to `main`, the check is **advisory** — a missing sign-off triggers
a warning in the GitHub Actions summary but does not fail the build
(this is a safety net so we don't accidentally block legitimate
hot-fixes if the CI itself is broken).

Bots (Dependabot, GitHub Actions, renovate, etc.) are exempt from
DCO enforcement. Merge commits are also exempt.

## Common questions

**Q: Why DCO instead of a CLA?**
A: DCO is one-line per commit, signed automatically with `-s`, and
   has no negotiation overhead. CLAs are appropriate when you need
   to acquire copyright (e.g., for project relicensing). AegisGate
   Lens is Apache 2.0 forever; we don't need copyright assignment.

**Q: My employer requires approval for outside contributions.**
A: Get approval BEFORE submitting. The DCO attests that you have
   the right to submit. Your employer's IP agreement with you
   determines that, not us.

**Q: Can I use a pseudonym?**
A: Yes, as long as the GitHub email matches. We respect
   "anonymous" disclosure per our SECURITY.md policy.

**Q: What if my commit is a typo fix in someone else's PR?**
A: The PR author needs to sign off the squashed merge commit. We
   recommend "Squash and merge" so only one sign-off is needed.

## Reference

- Linux kernel DCO: https://developercertificate.org/
- AegisGate Platform DCO: `DCO.md` in the Platform repo.
- Apache 2.0 license: `LICENSE` in this repo.
