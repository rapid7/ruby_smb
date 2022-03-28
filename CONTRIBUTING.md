# Contributing

## Versioning

RubySMB attempts to follow [the Semantic Versioning 2.0.0](https://semver.org/) standard, however due to certain key architectural qualities, some reservations are made regarding what will trigger major and minor version bumps. A large component of RubySMB are the data definitions written using [BinData](https://github.com/dmendel/bindata). These definitions are implemented in an incremental fashion, causing some to be missing while others are only partially implemented (particularly in cases where fields are dependent on other types that may or may not be defined). Because of this, the RubySMB project reserves the right to update these definitions without incrementing the major version. In most cases, the definitions and their fields do not need to be used to perform standard operations such as connecting to, authenticating to and reading a file from a remote SMB server. The API provided by non-BinData objects will remain stable across minor versions, with backwards incompatible changes triggering a major version bump. Backwards incompatible changes to data structure definitions in BinData will cause the RubySMB maintianers to perform a minor version bump. These changes include but are not limited to:

* Changes to the class name due to how BinData's internal registration works
* Their field names which may be updated to avoid conflicts
* Their field types which may be extended with more functionality or switched from integers to full-flag based definitions

### Usage Examples
The following two examples show dangerous operations that may not be stable across minor version bumps, and safe operations.

```
# dangerous operation, the BinData object name (TransformHeader) may change in the future
header = RubySMB::SMB2::Packet::TransformHeader.read(raw_request)
# also dangerous operation, the field name may change in the future
header.flags = 0
```

```
# safe operation, the API exposed on the Client won't change without a major version bump
client = RubySMB::Client.new(dispatcher, smb1: options[:smbv1], smb2: options[:smbv2], smb3: options[:smbv3], username: options[:username], password: options[:password], domain: options[:domain])
# safe operation, methods on non-BinData objects won't change without a major version bump
protocol = client.negotiate
```

## Forking

[Fork this repository](https://github.com/rapid7/ruby_smb/fork)

## Branching

Branch names follow the format `TYPE/ISSUE/SUMMARY`.  You can create it with `git checkout -b TYPE/ISSUE/SUMMARY`.

### `TYPE`

`TYPE` can be `bug`, `chore`, or `feature`.

### `ISSUE`

`ISSUE` is either a [Github issue](https://github.com/rapid7/ruby_smb/issues) or an issue from some other
issue tracking software.

### `SUMMARY`

`SUMMARY` is is short summary of the purpose of the branch composed of lower case words separated by '-' so that it is a valid `PRERELEASE` for the Gem version.

## Changes

### `PRERELEASE`

1. Update `PRERELEASE` to match the `SUMMARY` in the branch name.  If you branched from `master`, and [version.rb](lib/ruby_smb/version.rb) does not have `PRERELEASE` defined, then adding the following lines after `PATCH`:
```
# The prerelease version, scoped to the {MAJOR}, {MINOR}, and {PATCH} version number.
PRERELEASE = '<SUMMARY>'
```
2. `rake spec`
3.  Verify the specs pass, which indicates that `PRERELEASE` was updated correctly.
4. Commit the change `git commit -a`

### Your changes

Make your changes or however many commits you like, committing each with `git commit`.

### Pre-Pull Request Testing

1. Run specs one last time before opening the Pull Request: `rake spec`
2. Verify there was no failures.

### Push

Push your branch to your fork on gitub: `git push TYPE/ISSUE/SUMMARY`

### Pull Request

* [Create new Pull Request](https://github.com/rapid7/ruby_smb/compare/)
* Add a Verification Steps to the description comment

```
# Verification Steps

- [ ] `bundle install`

## `rake spec`
- [ ] `rake spec`
- [ ] VERIFY no failures
```

You should also include at least one scenario to manually check the changes outside of specs.

* Add a Post-merge Steps comment

The 'Post-merge Steps' are a reminder to the reviewer of the Pull Request of how to update the [`PRERELEASE`](lib/windows_error/version.rb) so that [version_spec.rb](spec/lib/windows_error/version.rb_spec.rb) passes on the target branch after the merge.

DESTINATION is the name of the destination branch into which the merge is being made.  SOURCE_SUMMARY is the SUMMARY from TYPE/ISSUE/SUMMARY branch name for the SOURCE branch that is being made.

When merging to `master`:

```
# Post-merge Steps

Perform these steps prior to pushing to master or the build will be broke on master.

## Version
- [ ] Edit `lib/ruby_smb/version.rb`
- [ ] Remove `PRERELEASE` and its comment as `PRERELEASE` is not defined on master.

## Gem build
- [ ] gem build *.gemspec
- [ ] VERIFY the gem has no '.pre' version suffix.

## RSpec
- [ ] `rake spec`
- [ ] VERIFY version examples pass without failures

## Commit & Push
- [ ] `git commit -a`
- [ ] `git push origin master`
```

When merging to DESTINATION other than `master`:

```
# Post-merge Steps

Perform these steps prior to pushing to DESTINATION or the build will be broke on DESTINATION.

## Version
- [ ] Edit `lib/windows_error/version.rb`
- [ ] Change `PRERELEASE` from `SOURCE_SUMMARY` to `DESTINATION_SUMMARY` to match the branch (DESTINATION) summary (DESTINATION_SUMMARY)

## Gem build
- [ ] gem build windows_error.gemspec
- [ ] VERIFY the prerelease suffix has change on the gem.

## RSpec
- [ ] `rake spec`
- [ ] VERIFY version examples pass without failures

## Commit & Push
- [ ] `git commit -a`
- [ ] `git push origin DESTINATION`
```
