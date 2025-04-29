# AceCov: Auxiliary Composite Edge Coverage for Fuzzing

## Overview
AceCov is an LLVM-based plugin for AFL++ designed to enhance the performance of fuzzers by extending AFL++'s coverage metrics. It provides advanced instrumentation and dependency analysis capabilities to improve fuzzing efficiency.

## Features
- **Dependency Analysis**: Performs comprehensive analysis of dependencies in LLVM IR, including PHI and SELECT instructions.
- **Instrumentation**: Extends AFL++'s coverage metrics seamlessly, enabling enhanced integration and performance.

## Installation
1. Ensure LLVM 15 is installed on your system.
2. Clone the AceCov repository.
3. Navigate to the `analysis` directory and build the plugin by running `make`.
4. Clone the AFL++ repository.
5. Apply the `aflpp.diff` patch to AFL++.
6. Build AFL++ by running `make` in its root directory.
7. Move the generated plugin file to the AFL++ root directory.

### Commands
- At the AceCov directory:
```bash
cd analysis
make
mv plugin.so /path/to/AFL++
```

- At the AFL++ directory:
```bash
git apply /path/to/acecov/aflpp.diff
make
```

## Usage
1. Compile your target project with AFL++, including the AceCov plugin.
2. Execute the fuzzer as you would with the original AFL++.

## Experimental Data
For detailed experimental data and results, please refer to the following repository:  
[acecov_experiment_data](https://github.com/shioya-lab-public/acecov_experiment_data)

## Scripts for Fuzzing Evaluation Frameworks
AceCov provides scripts for integration with fuzzing evaluation frameworks such as [FuzzBench](https://github.com/google/fuzzbench) and [MAGMA](https://github.com/HexHive/magma). These scripts are available at:  
[acecov_experiment](https://github.com/shioya-lab-public/acecov_experiment)

## License
This project is licensed under the Apache License 2.0. For more details, see the LICENSE file included in the repository.

## Contact
For inquiries or contributions, please contact the authors.
