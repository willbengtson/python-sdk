"""
Copyright 2017-2018 CAPITAL LAB OÜ

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


class ApilityioError(Exception):
  """Parent class of all errors raised by this library."""
  pass


class ApilityioValueError(ApilityioError):
  """Error indicating that the user input for a function was invalid."""
  pass
