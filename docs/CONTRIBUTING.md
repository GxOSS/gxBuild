## How to contribute to gxBuild

Taken from [EdgeTX](https://github.com/EdgeTX/.github/)


#### **Did you find a bug?**

* **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/ExposureMG/gxBuild/issues).

* If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/ExposureMG/gxBuild/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, including steps to reproduce the issue. Pictures or a short vidoe to demonstrate the issue are welcome. 


#### **AI Policy**

gxBuild has no concrete policy on AI; The only requirement for a change is that the code is properly licensed and of a high standard. I understand that in 2026, with Human assistance, AI has advanced enough to write high quality code.

You are responsible for your patches; You may submit AI generated code, but you are responsible for testing, bugfixing, and ensuring it meets the project standards.


#### **Did you write a patch that fixes a bug?**

* Open a new GitHub pull request with the patch.

* Ensure the PR description clearly describes the problem and solution. Include the relevant issue number if applicable.


#### **Did you fix whitespace, format code, or make a purely cosmetic patch?**

Changes that are cosmetic in nature and do not add anything substantial to the stability, functionality, or testability of gxBuild will generally not be accepted.

In order for a cosmetic change to be accepted, it must substantially improve or cleanup the codebase. Judged case by case.


#### **Do you intend to add a new feature or change an existing one?**

Pull Requests adding new functionality or improving existing ones are always welcome. However, before spending any significant time on a new feature or change, it would probably be best to discuss/propose your idea to the development team on [gxBuild Discord](https://discord.gg/wF9wUKnZ6H) to ascertain the likelihood of any significant changes being accepted/incorporated into the codebase. 

Please do not open an issue on GitHub until you have collected positive feedback about the change. GitHub issues are primarily intended for bug reports and fixes, although it is also used by end users for feature requests / changes. 


#### **Do we have any conventions or requirements when submitting code?**
 * Any new code added needs to either be your own work, or otherwise usable under a GPL 2 license. 

 * Any newly added or modified code must use/retain the boilerplate copyright header included in the repo at `tools/copyright-header.txt`. There is no need to self-attribute authorship as this is self-evident from the git commit log, and is just adding unnecessary noise to the PR content.

 * Code should be formatted as per the `.clang-format` in the repo root. If you are modifying existing code, try to fit in with any style (i.e. camelCase, indentation) where resonable. Don't be afraid to reformat a block of code to match the autoformatter as there is a lot of legacy code in the codebase. 

 * Please keep Pull Requests single focus - i.e. if you are adding a feature for say colorlcd radios, do not incorporate a bugfix for B&W screens in that PR... It is better to have multiple, smaller, single focus PRs than larger, "spaghetti" , PRs, and this will make the testing and merge review quicker and easier.
 
 * Pull Requests are generally squash merged, so there is no need to flatten your work before merge. It would be appreciated if the PR is held back for any significant duration if you would periodically rebase it against the main development branch, especially if any merge conflicts arise.
 
 * We are using the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification for PR titles, so please keep this in mind when titling your PR. Where possible, please keep PR titles between 50 and 72 characters. 

 * GitHub (and to some extent `git`) doesn't like files that don't have a newline at the end of file... don't be that person that makes me fix that up when I see that annoying red mark in the review screen :laughing:
 

#### **Do you have questions about the source code?**

There is some documenation will help you get a development started on the [EdgeTX Wiki](https://github.com/EdgeTX/edgetx/wiki). To see helper scripts for building firmware and companion, have a look at the `tools/build-gh.sh` and `tools/build-companion.sh` scripts which are used daily by CI.

Ask any questions you have about the codebase on the [EdgeTX Discord](https://discord.gg/wF9wUKnZ6H), and someone will be sure to help you out. Please bear in mind we are an international team of developers who are volunteering our time to the project, so it may take several hours before someone can reply. 


#### **Do you want to contribute to the EdgeTX documentation?**

EdgeTX is a volunteer effort. We encourage you to pitch in and join us in making this the best firmware for Radio Control handsets!

Thanks! :heart: :heart: :heart:

EdgeTX Team
