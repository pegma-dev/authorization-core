## Summary

<!-- What changed, and why? -->

## Authorization and compatibility impact

<!--
Describe changes to granted permissions, trust boundaries, public contracts,
provider behavior, or migration requirements. Write "None" when not applicable.
-->

## Validation

<!-- List the checks you ran. -->

- [ ] `npm run check`
- [ ] `npm test`
- [ ] `npm run format:check`

## Checklist

- [ ] New permission-granting behavior includes allow and deny tests.
- [ ] Public API changes include documentation and migration impact.
- [ ] No provider-specific types leaked into core contracts.
- [ ] No secrets, credentials, or customer data are included.
