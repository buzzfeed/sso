# Contributing

Thank you for your interest in contributing to BuzzFeed's SSO!

## Code of Conduct

Help us keep SSO open and inclusive. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### The Basics

If you've never contributed to a project on Github before, take a look at [Rob Allen's beginner's guide to contributing to a Github project][begin-guide].

* Make sure you have a [GitHub account](https://github.com/signup/free)
* Submit a ticket for your issue, assuming one does not already exist. In that issue:
  * Clearly describe the issue including steps to reproduce when it is a bug
  * Identify specific versions of the binaries and client libraries
* Fork the repository on GitHub

### Making Changes

* Create a branch from where you want to base your work
  * We typically name branches according to the following format: `helpful_name_<issue_number>`
* Make commits of logical units
* Make sure your [commit messages](https://chris.beams.io/posts/git-commit/) are in a clear and readable format, example:

```
sso: added structured logging

* use Logrus to add structured logging
* update logging documentation
* ...
```

### Quickstart

If you want to get SSO up and running, please see our [quickstart guide](docs/quickstart.md).

### Running Tests

All bug fixes and new features are expected to include tests, so it's helpful to know how to run them locally while you're developing!

Here are the steps to running the tests for SSO:

1. [Install go][go]
2. Be sure to set your workspace directory and set your GOPATH
3. Add the sso repo to your gopath:

   ```sh
   ln -s path/to/sso $GOPATH/src/github.com/buzzfeed/sso
   ```

4. Install gpm and dependencies:

   ```sh
   brew install gpm
   gpm install
   ```

5. Run the tests in the root directory

   ```sh
   ./scripts/test
   ```

### Submitting Changes

* Push your changes to your branch in your fork of the repository
* Submit a [pull request against BuzzFeed's repository](https://akrabat.com/the-beginners-guide-to-contributing-to-a-github-project/#step-3-create-the-pr)
* Comment in the pull request when you're ready for the changes to be reviewed: `"ready for review"`

### Code review

Changes to `buzzfeed/sso` happen via GitHub pull requests, which is where at least one other engineer reviews and approves all code changes. Some tips for pull requests and code review:

* Each pull request is a branch from `master` — there are no other long-lived branches
* A single pull request is used for each set of changes — i.e., once a pull request has been opened, any follow-up commits to address code review and discussion should be pushed to that pull request instead of a new one
* Before a pull request is merged, it must get a green check mark from our CI for passing tests
* Before a pull request is merged, the author should take the opportunity to clean up and rewrite the commits on the branch (see [How to Write a Git Commit Message](https://chris.beams.io/posts/git-commit/).
* A maintainer will merge your changes once they're approved and ready!
* **Most importantly: Practice [mindful communication][mindful-comms]!**

[begin-guide]: https://akrabat.com/the-beginners-guide-to-contributing-to-a-github-project/
[mindful-comms]: https://kickstarter.engineering/a-guide-to-mindful-communication-in-code-reviews-48aab5282e5e
[go]: https://golang.org/doc/install