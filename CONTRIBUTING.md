# How To Contribute<sup>[1](#footnote-1)</sup>

First off, thank you for considering contributing to `drf-user`! It's people
like _you_ who make it such a great tool for everyone.

This document intends to make contribution more accessible by codifying tribal
knowledge and expectations. Don't be afraid to open half-finished PRs, and ask
questions if something is unclear!

## Workflow

- No contribution is too small! Please submit as many fixes for typos and
  grammar bloopers as you can!
- Try to limit each pull request to **_one_** change only.
- Since we squash on merge, it's up to you how you handle updates to the master
  branch. Whether you prefer to rebase on master or merge master into your
  branch, do whatever is more comfortable for you.
- _Always_ add tests and docs for your code. This is a hard rule; patches with
  missing tests or documentation will not be merged.
- Make sure your changes pass our
  [CI](https://github.com/101loop/drf-user/actions?query=workflow%3ACI). You
  won't get any feedback until it's green unless you ask for it.
- Once you've addressed review feedback, make sure to bump the pull request with
  a short note, so we know you're done.
- Avoid breaking backwards compatibility.

## Code

- Obey [PEP 8](https://www.python.org/dev/peps/pep-0008/),
  [PEP 257](https://www.python.org/dev/peps/pep-0257/), and the
  [Numpydoc Docstring Guide](https://numpydoc.readthedocs.io/en/latest/format.html).
  We have a summary line starting the `"""` block:

  ```python
  def foo(var1, var2, *args, long_var_name='hi', **kwargs):
      """Summarize the function in one line.

      Several sentences providing an extended description. Refer to
      variables using back-ticks, e.g. `var`.

      Parameters
      ----------
      var1 : array_like
          Array_like means all those objects -- lists, nested lists, etc. --
          that can be converted to an array.  We can also refer to
          variables like `var1`.
      var2 : int
          The type above can either refer to an actual Python type
          (e.g. ``int``), or describe the type of the variable in more
          detail, e.g. ``(N,) ndarray`` or ``array_like``.
      *args : iterable
          Other arguments.
      long_var_name : {'hi', 'ho'}, optional
          Choices in brackets, default first when optional.
      **kwargs : dict
          Keyword arguments.

      Returns
      -------
      type
          Explanation of anonymous return value of type ``type``.
      describe : type
          Explanation of return value named `describe`.
      out : type
          Explanation of `out`.
      type_without_description

      Raises
      ------
      BadException
          Because you shouldn't have done that.

      Notes
      -----
      Notes about the implementation algorithm (if needed).

      This can have multiple paragraphs.

      You may include some math:

      .. math:: X(e^{j\omega } ) = x(n)e^{ - j\omega n}

      And even use a Greek symbol like :math:`\omega` inline.

      Examples
      --------
      These are written in doctest format, and should illustrate how to
      use the function.

      >>> a = [1, 2, 3]
      >>> print([x + 3 for x in a])
      [4, 5, 6]
      >>> print("a\nb")
      a
      b
      """
      # After closing class docstring, there should be one blank line to
      # separate following codes (according to PEP257).
      # But for function, method and module, there should be no blank lines
      # after closing the docstring.
  ```
  
- We follow
[reorder_python_imports](https://github.com/asottile/reorder_python_imports) for
sorting our imports. Similar to [isort](https://github.com/timothycrosley/isort)
but uses static analysis more, and we follow the
[Black](https://github.com/psf/black) code style with a line length of 88
characters.
<!-- As long as you run our full tox suite before committing, or install our [pre-commit](https://pre-commit.com/) hooks (ideally you'll do both -- see [Local Development Environment](#local-development-environment)), you won't have to spend any time on formatting your code at all. If you don't, CI will catch it for you -- but that seems like a waste of your time! -->

## Tests

- Write your asserts as `expected == actual` to line them up nicely:

```python

 x = f()

 assert 42 == x.some_attribute
 assert "foo" == x._a_private_attribute
```

<!-- * To run the test suite, all you need is a recent [tox](https://tox.readthedocs.io/). It will ensure the test suite runs with all dependencies against all Python versions just as it will in our CI. If you lack some Python versions, you can can always limit the environments like ``tox -e py35,py36`` (in that case you may want to look into [pyenv](https://github.com/pyenv/pyenv), which makes it very easy to install many different Python versions in parallel). -->

- Write [good test docstrings](https://jml.io/pages/test-docstrings.html).

## Documentation

Project-related documentation is written in
[restructuredtext](https://docutils.sourceforge.io/rst.html) (`.rst`).
GitHub-related project documentation (e.g. this file you're reading,
`CONTRIBUTING.md`) is written in Markdown, as GitHub doesn't support `.rst`
files for some of their features (e.g. automatically picking up the
`CODE_OF_CONDUCT.md`)

- If you start a new section, add two blank lines before and one blank line
  after the header, except if two headers follow immediately after each other:

  ```rst
   Last line of previous section.

   Header of New Top Section
   -------------------------

   Header of New Section
   ^^^^^^^^^^^^^^^^^^^^^

   First line of new section.
  ```

- If you add a new feature, demonstrate its awesomeness under `usage.rst`!

## Local Development Environment

<!-- You can (and should) run our test suite using [tox](https://tox.readthedocs.io/). However, you’ll probably want a more traditional environment as well. We highly recommend to develop using the latest Python 3 release because `interrogate` tries to take advantage of modern features whenever possible. -->

First create a [virtual environment](https://virtualenv.pypa.io/). It’s out of
scope for this document to list all the ways to manage virtual environments in
Python, but if you don’t already have a pet way, take some time to look at tools
like [pyenv-virtualenv](https://github.com/pyenv/pyenv-virtualenv),
[pew](https://github.com/berdario/pew),
[virtualfish](https://virtualfish.readthedocs.io/),
[virtualenvwrapper](https://virtualenvwrapper.readthedocs.io/), and
[pyenv-virtualenvwrapper](https://github.com/pyenv/pyenv-virtualenvwrapper).

Next, get an up to date checkout of the `drf-user` repository:

```sh
$ git clone git@github.com:101loop/drf-user.git
```

or if you want to use git via `https`:

```sh
$ git clone https://github.com/101loop/drf-user.git
```

Change into the newly created directory and **after activating your virtual
environment** install an editable version of `drf-user` along with its tests,
docs requirements and to avoid committing code that violates our style guide, we
use [pre-commit](https://pre-commit.com/) hooks:

```sh
(env) $ cd drf-user
(env) $ make install
```

At this point,

```sh
(env) $ make test
```

should work and pass, as should:

```sh
(env) $ cd docs
(env) $ make livehtml
```

The built documentation can then be found in
[`localhost:8888`](http://localhost:8888).

Create a branch for local development:

```sh
(env) $ git checkout -b name-of-your-bugfix-or-feature
```

Now you can make your changes locally.

When you're done making changes, check that your changes pass tests and code
style should be aligned with Flake8 and Black:

```sh
(env) $ make check
```

Commit your changes and push your branch to GitHub:

```sh
(env) $ git add .
(env) $ git commit -m "Your detailed description of your changes."
(env) $ git push origin name-of-your-bugfix-or-feature
```

Submit a pull request through the GitHub website.

## Code of Conduct

Please note that this project is released with a Contributor
[Code of Conduct](https://github.com/101loop/drf-user/blob/master/CODE_OF_CONDUCT.md).
By participating in this project you agree to abide by its terms. Please report
any harm to `devs [at] 101loop.com` for anything you find appropriate.

Thank you for considering contributing to `drf-user`!

---

<a name="footnote-1">1</a>: This contribution guide has been taken from
[interrogate](https://github.com/econchick/interrogate/).
