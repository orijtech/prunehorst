# prunehorst
Prune HORST -- Go port of Jean-Phillipe Aumasson and Guillaume Endignoux's new Post Quantum algorithm

## Original NIST submission
Prunehorst by Jean-Phillipe Aumasson and Guillaume Endignoux was submitted to NIST with references at:
* [Code](https://github.com/gravity-postquantum/prune-horst)
* [Listing](https://post-quantum.ch)

## Acknowledgements
This work is an on-going collaboration between:
* [Jean-Philippe Aumasson](https://github.com/veorq)  -- Kudelski Security
* [Emmanuel Odeke](https://github.com/odeke-em) -- orijtech, Inc

## Intermediate values
To generate the intermediate values, run:
```shell
make ivs
```
which will produce a file `IntermediateValues.txt` in your current working directory.

## LICENSE
Copyright 2017 Kudelski Security and orijtech, Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
