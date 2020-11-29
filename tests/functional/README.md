# Local KMS Functional Tests

There are two goals to these tests:
* Regression testing for Local KMS.
* Generating a set of tests that can be run against AWS KMS and Local KMS, to ensure the two match.

#### Why are they in Python?
There are a few reasons:
* It allows different encryption libraries to be used from those that generate keys in Local KMS. The demonstration that
generated keys are compatible with other libraries adds weight to the fact they're initially being generated correctly.
* Python's Duck typing allows us to spend less time thinking about all the data structures being passed around, so we can focus
on just the element we're currently testing.
* It's quite quick and easy.

## Setup

Bring up Local KMS with Docker Compose. From within the root of the repository:
```shell script
docker-compose up
````

From within local-kms/tests/functional:
```shell script
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirments.txt

pytest
```
