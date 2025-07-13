import re
import matplotlib.pyplot as plt

# Load input
with open("stat.txt") as f:
    raw_data = f.read()

# Second pass: Collect CUDA Non-Kernel Times manually and sort by size
cuda_non_kernel_data = []

lines = raw_data.strip().splitlines()
current_size = None
is_cuda_block = False

for line in lines:
    size_match = re.match(r"- (\d+)(?:\s*MB|\s*bytes) of plaintext", line, re.IGNORECASE)
    if size_match:
        size_val = int(size_match.group(1))
        if "bytes" in line.lower():
            size_val = size_val / (1024 * 1024)
        current_size = float(size_val)
        is_cuda_block = False

    elif line.strip().lower() == "cuda":
        is_cuda_block = True

    elif is_cuda_block and "Non-kernel" in line:
        match = re.search(r"Non-kernel.*time:\s+(-?[\d.]+)\s*s", line, re.IGNORECASE)
        if match and current_size is not None:
            try:
                time_val = float(match.group(1))
                cuda_non_kernel_data.append((current_size, time_val))
            except ValueError:
                pass
        is_cuda_block = False  # reset after finding it

# Sort by input size (first element of each tuple)
cuda_non_kernel_data.sort(key=lambda x: x[0])
cuda_non_kernel_sizes, cuda_non_kernel_times = zip(*cuda_non_kernel_data)


# Patterns
size_pattern = re.compile(r"-\s*(\d+)(?:\s*MB|\s*bytes) of plaintext", re.IGNORECASE)
method_pattern = re.compile(r"^(cuda|openmp|aes sequential)$", re.IGNORECASE)
total_pattern = re.compile(r"^Total time:\s+([\d.]+)\s*s", re.IGNORECASE)
kernel_pattern = re.compile(r"^Kernel(?: execution)? time:\s+([\d.]+)\s*s", re.IGNORECASE)
non_kernel_pattern = re.compile(r"^Non-kernel(?: execution)? time:\s+(-?[\d.]+)\s*s", re.IGNORECASE)

# Data container
data = {}
current_size = None
current_method = None

lines = raw_data.strip().splitlines()

for line in lines:
    line = line.strip()

    # Match input size
    size_match = size_pattern.match(line)
    if size_match:
        size_val = int(size_match.group(1))
        if "bytes" in line.lower():
            size_val = size_val / (1024 * 1024)  # Convert bytes to MB
        current_size = float(size_val)
        data.setdefault(current_size, {})
        current_method = None
        continue

    # Match method
    method_match = method_pattern.match(line)
    if method_match and current_size is not None:
        current_method = method_match.group(1).lower()
        data[current_size].setdefault(current_method, {"total": 0.0, "kernel": 0.0, "non_kernel": 0.0})
        continue

    # Match total time
    total_match = total_pattern.match(line)
    if total_match and current_size and current_method:
        data[current_size][current_method]["total"] = float(total_match.group(1))

    # Match kernel time
    kernel_match = kernel_pattern.match(line)
    if kernel_match and current_size and current_method:
        data[current_size][current_method]["kernel"] = float(kernel_match.group(1))

    # Match non-kernel time
    non_kernel_match = non_kernel_pattern.match(line)
    if non_kernel_match and current_size and current_method:
        # Use .group() without index if there's only one capture group
        value_str = non_kernel_match.group(1) if non_kernel_match.lastindex == 1 else non_kernel_match.group(non_kernel_match.lastindex)
        data[current_size][current_method]["non_kernel"] = float(value_str)
# ---- Plotting ----
methods = ['aes sequential', 'openmp', 'cuda']
sorted_sizes = sorted(data.keys())

# Plot 1: Total time
plt.figure(figsize=(10, 6))
for method in methods:
    y = [data[size].get(method, {}).get("total", 0.0) for size in sorted_sizes]
    plt.plot(sorted_sizes, y, marker='o', label=method)
plt.title("Total Execution Time by Method")
plt.xlabel("Input Size (MB)")
plt.ylabel("Time (s)")
plt.grid(True)
plt.legend()
plt.savefig("total_times.png")

# Plot 2: Kernel time
plt.figure(figsize=(10, 6))
for method in methods:
    y = [data[size].get(method, {}).get("kernel", 0.0) for size in sorted_sizes]
    plt.plot(sorted_sizes, y, marker='o', label=method)
plt.title("Kernel Execution Time by Method")
plt.xlabel("Input Size (MB)")
plt.ylabel("Kernel Time (s)")
plt.grid(True)
plt.legend()
plt.savefig("kernel_times.png")

# Plot 3: CUDA Non-Kernel time (from second pass)
plt.figure(figsize=(10, 6))
plt.plot(cuda_non_kernel_sizes, cuda_non_kernel_times, marker='o', color='purple', label='CUDA Non-Kernel Time')
plt.title("CUDA Non-Kernel Execution Time")
plt.xlabel("Input Size (MB)")
plt.ylabel("Non-Kernel Time (s)")
plt.grid(True)
plt.legend()
plt.savefig("cuda_non_kernel_time.png")

# Plot 4: Speedup histogram
openmp_speedup = []
cuda_speedup = []
valid_sizes = []

for size in sorted_sizes:
    d = data.get(size, {})
    if all(m in d for m in ['aes sequential', 'openmp', 'cuda']):
        serial_time = d['aes sequential']['total']
        openmp_time = d['openmp']['total']
        cuda_time = d['cuda']['total']
        if serial_time > 0:
            valid_sizes.append(size)
            openmp_speedup.append(serial_time / openmp_time if openmp_time else 0)
            cuda_speedup.append(serial_time / cuda_time if cuda_time else 0)

x = range(len(valid_sizes))
width = 0.35
plt.figure(figsize=(10, 6))
plt.bar([i - width/2 for i in x], openmp_speedup, width=width, label='OpenMP')
plt.bar([i + width/2 for i in x], cuda_speedup, width=width, label='CUDA')
plt.xticks(x, [str(int(s)) for s in valid_sizes])
plt.title("Speedup vs AES Sequential (Total Time)")
plt.xlabel("Input Size (MB)")
plt.ylabel("Speedup")
plt.grid(axis='y')
plt.legend()
plt.savefig("speedup_histogram.png")

plt.show()
