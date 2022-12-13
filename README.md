An AEGIS-128L implementation for recent Intel and AMD CPUs wtih AVX2 and VAES.

Currently slower than non-VAES implementations due to the requirement of 128-bit rotations across 256-bit registers.