# Release Process

1. Open PR that
   1. adds release notes to `doc/CHANGELOG.md` and
   2. updates `_PKG_VERSION_{MAJOR,MINOR,BUILD}` and `_LIB_VERSIONS_*` in `configure.ac`
2. After merge, create a release branch with name `MAJOR.MINOR.PATCH`. Make sure that the branch contains the right commits.
3. Create commit on the release branch that sets `_PKG_VERSION_IS_RELEASE` in `configure.ac` to `true`.
4. Tag the commit with `git tag -s vMAJOR.MINOR.PATCH`.
5. Push branch and tag with `git push origin --tags`.
6. Create a new GitHub release with a link to the corresponding entry in `doc/CHANGELOG.md`.
