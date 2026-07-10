## Summary

Describe the problem and the behavioral change.

## Validation

List commands run and relevant fixture or integration coverage.

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all`
- [ ] `cargo audit` when dependencies or release metadata changed

## Safety and Compatibility

- [ ] The change preserves runtime enforcement over reasoning output.
- [ ] The change does not expose secrets or unredacted sensitive target data.
- [ ] Documentation and generated-artifact contracts were updated where needed.
- [ ] New or changed target behavior has fixture coverage.
- [ ] Compatibility or migration effects are described above.
