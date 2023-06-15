# OPAConfTest
Testing the OPA conftest policy checker

Download the test files into a new directory, structure should be
 /testdirectory/deployment.yaml
 /testdirectory/policy/testpolicy.rego
 
 To run test ** note change testdirectory to your specified.
 docker run --rm -v ~/testdirectory:/project openpolicyagent/conftest test deployment.yaml
