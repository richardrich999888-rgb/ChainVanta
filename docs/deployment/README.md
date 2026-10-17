# deployment

Status: **Planned; not a deployed service or implemented capability.**

Target-specific deployment instructions after a target is selected.

`.github/workflows/deploy-staging.yml` is manual and deliberately fails until staging deployment
is implemented. Before replacing the guard, select the target and implement infrastructure,
secret delivery, migrations, health verification and rollback. The release workflow currently
uploads a build candidate only; it does not publish or deploy a release.

See the [root README](../../README.md) for the working milestone and activation criteria.
