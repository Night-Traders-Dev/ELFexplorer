set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR riscv32)

set(CMAKE_C_COMPILER riscv64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER riscv64-linux-gnu-g++)
set(CMAKE_ASM_COMPILER riscv64-linux-gnu-gcc)

set(CMAKE_C_FLAGS_INIT "-march=rv32gc -mabi=ilp32d")
set(CMAKE_CXX_FLAGS_INIT "-march=rv32gc -mabi=ilp32d")
set(CMAKE_ASM_FLAGS_INIT "-march=rv32gc -mabi=ilp32d")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-march=rv32gc -mabi=ilp32d")
