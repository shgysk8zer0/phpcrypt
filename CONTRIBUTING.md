# Contributing to the project
**Table of Contents**
-   [General](#general)
-   [Requirements](#requirements)
-   [PHP Contributions](#php)
- - -

## General
Write access to the GitHub repository is restricted, so make a fork and clone that. All work should be done on its own branch, named according to the issue number (*e.g. `feature/42` or `bug/23`*). When you are finished with your work, push your feature branch to your fork, preserving branch name (*not to master*), and create a pull request.

**Always pull from `upstream master` prior to sending pull-requests.**

## Requirements
-   [PHP 7](https://secure.php.net/)
-   [OpenSSL](https://secure.php.net/manual/en/book.openssl.php)
-   [Git](https://www.git-scm.com/download/)

## PHP
Since this requires PHP 7 or greater, make use of the great [new features](https://secure.php.net/manual/en/migration70.new-features.php)
as much as possible and appropriate. Namely, **do** use scalar type declarations
and return type declarations.

This project uses PHP's native autoloader [`spl_autoload`](https://secure.php.net/manual/en/function.spl-autoload.php).
To use `spl_autoload`, just make sure that the project's parent directory
is in your include path (*check using `print_r(explode(PATH_SEPARATOR, get_include_path()));`*). To setup auto-loading, just use `spl_autoload_register('spl_autoload');`

See [index.php](./index.php) for example.

All pull requests **MUST** pass `php -l` linting, not raise any `E_STRICT` errors when run, avoid usage or global variables, and not declare any constants
or functions in the global namespaces. All declared constants and functions must be in a file whose namespace is set according to its path, relative to `DOCUMENT_ROOT`.

Travis-CI runs tests that are required to pass in order to merge any pull
requests.
