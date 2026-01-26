# Local KMS (LKMS)

> [!NOTE]
> V4 work in progress.

V3 will continue to be supported for security updates, but will recieve no more feature updates.

## Refactor overview

The current refactor lays the groundwork for the v4 architecture, focusing on long-term
maintainability and easier growth of the service. It reorganises the project into clearer
modules and brings in a broader set of common request handlers to close feature gaps. The
goal is to make ongoing development simpler while enabling faster support for new key types,
including post-quantum options like ML-DSA.

## v3 support status

v3 will continue to receive **security updates**, but it will **not receive any further
feature development**.

## Breaking changes

> [!WARNING]
> v4 introduces backwards-incompatible changes. (Thus why it's a major version bump)

This release intentionally breaks compatibility with v3 in order to unblock a number of
long-standing issues and enable future development.

Key impacts:

- **Database changes**  
  v4 moves to a different, actively supported database backend. This allows us to remove
  legacy persistence patterns and simplify the internal data model.  
  You are only likely to be affected if you have **long-running or persisted databases**
  created with earlier versions.

- **Seeding format changes**  
  The seeding file format has been redesigned to better support the regular addition of new
  key types (including post-quantum algorithms).  
  A **v3 → v4 seeding file converter** will be provided to ease migration.

Overall, these breaking changes are deliberate and aim to improve correctness,
maintainability, and extensibility going forward, while keeping migration effort minimal
for most users.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
